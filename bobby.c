#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <getopt.h>
#include <glib.h>
#include <gmodule.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/ethernet.h>

#include "common.h"
#include "if_arp.h"
#include "bobby.bpf.skel.h"

typedef struct {
	struct ether_header eth;
	struct arphdr arp;
} packet_t;

typedef struct
{
	u_int32_t value;
	u_int32_t netmask;
} cidr_t;

/* configurations for sponge mode */
#define TYPE_REPLY 	(1 << 1)
#define TYPE_REQUEST 	(1 << 2)
#define TYPE_GRATUITOUS	(1 << 4)
#define TYPE_ALL 	(TYPE_REPLY | TYPE_REQUEST | TYPE_GRATUITOUS)
#define TYPE_NONE	0

typedef struct
{
	gchar *name;
	guchar hw_addr[6];
	u_int32_t if_index;
	u_int32_t sponge;
	bool broadcast;
	bool enabled;
	bool verbose;
	bool debug;
	GList *cidr;
} if_conf_t;

typedef struct
{
	u_int32_t key;
	u_int64_t ts;
	int64_t level;
	unsigned char ip[4];
} store_data_t;

typedef struct
{
	u_int64_t weight;
	u_int64_t limit;
	u_int64_t leak;
	u_int32_t status_timer;
	int sock;

	GHashTable *interface;
	GHashTable *store;
} conf_t;

typedef struct
{
	u_int64_t requests;
	u_int64_t replies;
} stat_counters_t;

/* Global variables */
static volatile bool exiting = false;
static GTimer *status_timer = NULL;
static conf_t conf = {0};
static stat_counters_t stats = {0};


#define MAKE4(x) (x[0] << 24 | x[1] << 16 | x[2] << 8 | x[3])

#define print_and_exit(format, ...) { fprintf(stderr, format __VA_OPT__(,) __VA_ARGS__); exit(-1); }
#define print_and_leave(format, ...) { fprintf(stderr, format __VA_OPT__(,) __VA_ARGS__); exiting = true; return 0; }

int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

void
bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
		print_and_exit("Failed to increase RLIMIT_MEMLOCK limit!\n");
}

static void
sig_handler(int sig)
{
	exiting = true;
}

void
print_raw_packet(void *packet, u_int32_t packet_len)
{
	char buf[packet_len];
	memcpy(buf, packet, packet_len);
	for (int i = 0; i < packet_len; i++)
	{
		if (!(i % 4))
			printf("\n");
		printf("%.2x ", buf[i] & 0xff);
	}
	printf("\n");
}

int
handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	if (e->ar_op == ARPOP_REPLY)
	{
		u_int32_t ipaddr = MAKE4(e->ar_sip);
		store_data_t *entry = g_hash_table_lookup(conf.store, &ipaddr);
		if (entry == NULL)
			return 0;

		if_conf_t *if_conf = g_hash_table_lookup(conf.interface, &e->ifindex);
		if (if_conf == NULL)
			return 0;

		g_hash_table_remove(conf.store, &ipaddr);
	}
	else if (e->ar_op == ARPOP_REQUEST)
	{
		u_int32_t ipaddr = MAKE4(e->ar_tip);
		store_data_t *entry = g_hash_table_lookup(conf.store, &ipaddr);

		stats.requests++;
	
		if (entry == NULL)
		{
			entry = g_malloc0(sizeof(store_data_t));
			entry->key = ipaddr;
			entry->ts = e->ts;
			entry->level = 0;
			memcpy(entry->ip, e->ar_tip, sizeof(entry->ip));
			g_hash_table_insert(conf.store, &entry->key, entry);
		}
	
		if_conf_t *if_conf = g_hash_table_lookup(conf.interface, &e->ifindex);
		if (if_conf == NULL)
			print_and_leave("Problem looking up %u\n", e->ifindex);
	
		int found = 0;
		for (GList *list = if_conf->cidr; list != NULL; list = list->next)
		{
			cidr_t *cidr = list->data;
			u_int32_t destip = MAKE4(e->ar_tip) & (0xffffffff << (32 - cidr->netmask));
			if (cidr->value == destip)
			{
				found = 1;
				break;
			}
		}
		if (!found)
			fprintf(stderr, "Incorrect subnet for %d.%d.%d.%d\n", 
					entry->ip[0], entry->ip[1], entry->ip[2], entry->ip[3]);
	
		/* Leak from the bucket */
		entry->level -= conf.leak * (e->ts - entry->ts);
	
		/* Set the timestamp to current */
		entry->ts = e->ts;
	
		/* Handle underflows */
		if (entry->level < 0)
			entry->level = 0;
	
		/* Add weight last to handle long time idle queries */
		entry->level += conf.weight;
	
		if (entry->level >= conf.limit) /* limit */
		{
			stats.replies++;
	
			if (if_conf->verbose)
			{
				struct tm *tm;
				char ts[100];
				time_t t;
	
				time(&t);
				tm = localtime(&t);
				strftime(ts, sizeof(ts), "%c", tm);
				printf("[%-2s] weight: %li, sponging: %d.%d.%d.%d\n", 
					ts, entry->level, entry->ip[0], entry->ip[1], entry->ip[2], entry->ip[3]);
			}
	
			entry->level = 0;
	
			if (if_conf->debug)
				printf("Would respond with: %02x:%02x:%02x:%02x:%02x:%02x\n", 
					if_conf->hw_addr[0], if_conf->hw_addr[1], if_conf->hw_addr[2], 
					if_conf->hw_addr[3], if_conf->hw_addr[4], if_conf->hw_addr[5]);
	
			if (if_conf->sponge & TYPE_ALL)
			{
				int bit = 1;
				u_int32_t max_sponge = if_conf->sponge;
	
				while (max_sponge)
				{
					/* loop over any set bits, and process them with the same code */
					u_int32_t sponge = max_sponge & 1 << bit;
	
					if (if_conf->debug)
					{
						printf("--------------\ntype: %s%s%s\n", 
								sponge & TYPE_REPLY ? "reply" : "", 
								sponge & TYPE_REQUEST ? "request" : "",
								sponge & TYPE_GRATUITOUS ? "gratuitous" : "");
					}
					max_sponge = max_sponge ^ sponge;
					bit <<= 1;
					
					if (sponge == 0 )
						continue;
	
					/*
					 * From the arpsponge documentation:
					 *
					 * "reply"
					 * Send an unsollicited unicast reply to IP-B:
					 * ARP <IP-A> IS AT <MAC-A>
					 *
					 * Where IP-A and MAC-A are of the router targeted by the stray packet, 
					 * and IP-B is the IP address of the neighbour whose cache needs to be updated.
					 *
					 * "request"
					 * Send a unicast request by proxy (i.e. fake the requestor):
					 * ARP WHO HAS <IP-B> TELL <IP-A>@<MAC-A>
					 *
					 * Where IP-B is the IP address of the neighbour whose cache needs to be updated.
					 *
					 * "gratuitous" reference: https://wiki.wireshark.org/Gratuitous_ARP
					 * Send a unicast gratuitous ARP request on behalf of IP-A to IP-B:
					 * ARP WHO HAS <IP-A> TELL <IP-A>@<MAC-A>
					 *
					 * Where IP-B is the IP address of the neighbour whose cache needs to be updated.
					 *
					 * Arpsponge specifies request and gratuitous as unicast, we support bot unicast
					 * and broadcast.
					 */
	
					struct sockaddr_ll sa;
	
					memset(&sa, 0, sizeof(sa));
					sa.sll_family = AF_PACKET;
					sa.sll_protocol = ETH_P_ARP;
					sa.sll_ifindex = e->ifindex;
					memcpy(sa.sll_addr, if_conf->hw_addr, ETH_ALEN);
	
					packet_t packet;
	
					if (if_conf->broadcast && sponge & (TYPE_REQUEST|TYPE_GRATUITOUS))
						memset(packet.eth.ether_dhost, 0xff, ETH_ALEN);
					else
						memcpy(packet.eth.ether_dhost, e->ar_sha, ETH_ALEN);
	
					memcpy(packet.eth.ether_shost, sa.sll_addr, ETH_ALEN);
					packet.eth.ether_type = ntohs(ETHERTYPE_ARP);
	
					packet.arp.ar_hrd = ntohs(ARPHRD_ETHER);
					packet.arp.ar_pro = ntohs(ETH_P_IP);
					packet.arp.ar_hln = ETH_ALEN;
					packet.arp.ar_pln = 4;
	
					if (sponge & (TYPE_REPLY|TYPE_GRATUITOUS))
						packet.arp.ar_op = ntohs(ARPOP_REPLY);
					else	/* request */
						packet.arp.ar_op = ntohs(ARPOP_REQUEST);
	
					memcpy(packet.arp.ar_sha, packet.eth.ether_shost, ETH_ALEN);
					memcpy(packet.arp.ar_tha, packet.eth.ether_dhost, ETH_ALEN);
					memcpy(packet.arp.ar_sip, e->ar_tip, 4);
	
					if (sponge & (TYPE_REPLY|TYPE_REQUEST))
						memcpy(packet.arp.ar_tip, e->ar_sip, 4);
					else
						memcpy(packet.arp.ar_tip, e->ar_tip, 4);
					
					if (if_conf->debug)
						print_raw_packet(&packet, sizeof(packet));
	
					if (if_conf->enabled)
					{
						if (sendto(conf.sock, &packet, sizeof(packet), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
							fprintf(stderr, "Failed to send arp reply to \nn");
					}
					else if (if_conf->debug)
						printf("Interface not enabled, no packet sent\n");
				}
				/* remove handled hosts */
				g_hash_table_remove(conf.store, &ipaddr);
			}
		}
	}
	return 0;
}

void
load_conf(gchar *filename)
{

	GError * error = NULL;
	GKeyFile *key_file = g_key_file_new();
	gsize group_len = 0;

	g_key_file_set_list_separator(key_file, ',');
	if (!g_key_file_load_from_file(key_file, filename, 0, &error))
	{
		if (!g_error_matches(error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			fprintf (stderr, "Error loading key file: %s\n", error->message);
		exit(-1);
	}

	gchar **groups = g_key_file_get_groups(key_file, &group_len);
	for (int i = 0; i < group_len ; i++)
	{
		if (strcmp(groups[i], "global") == 0)
		{
			if ((conf.weight = g_key_file_get_uint64(key_file, groups[i], "weight", &error)) == 0)
				print_and_exit("Weight is 0? %s\n", error->message);
			if ((conf.limit = g_key_file_get_uint64(key_file, groups[i], "limit", &error)) == 0)
				print_and_exit("Limit is 0? %s\n", error->message);
			if ((conf.leak = g_key_file_get_uint64(key_file, groups[i], "leak", &error)) == 0)
				print_and_exit("Leak is 0? %s\n", error->message);
			if (g_key_file_has_key(key_file, groups[i], "status_timer", &error))
			{
				char *time = g_key_file_get_string(key_file, groups[i], "status_timer", &error);
				conf.status_timer = atoi(time);
				g_free(time);
			}
		}
		else if (g_str_has_prefix(groups[i], "interface"))
		{
			gsize list_len = 0;
			gchar **string_list = NULL;
			gchar *if_name = NULL;
			gchar buf[512];

			if (g_key_file_has_key(key_file, groups[i], "name", &error))
				if_name = g_key_file_get_string(key_file, groups[i], "name", &error);
			else
			{
				/* strtok is destructive, so use a buffer */
				strncpy(buf, groups[i], sizeof(buf));

				gchar *tmp = strtok(buf, "[ ]");
				tmp = strtok(NULL, "[ ]");

				if_name = g_strdup(tmp);
			}
			if (!if_name)
				print_and_exit("Missing interface definition! the correct format is [interface <if_name>]"
					       " or name = <if_name> in the interface section.\n");

			/* allocate */
			if_conf_t *if_conf = g_malloc0(sizeof(if_conf_t));
			if_conf->name = if_name;
			if ((if_conf->if_index = if_nametoindex(if_name)) == 0)
				print_and_exit("Interface '%s' not found!\n", if_name);

			/* look for hw_addr */
			struct ifaddrs *ifaddr, *ifa;
			if (getifaddrs(&ifaddr) == -1)
				print_and_exit("Failed to use getifaddrs()\n");
			for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
			{
				if (strcmp(if_name,ifa->ifa_name) == 0)
				{
					struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
					memcpy(if_conf->hw_addr, s->sll_addr, s->sll_halen);
				}
			}
			freeifaddrs(ifaddr);

			/* broadcast */
			if (g_key_file_has_key(key_file, groups[i], "broadcast", &error))
				if_conf->broadcast = g_key_file_get_boolean(key_file, groups[i], "broadcast", &error);
			else
				if_conf->broadcast = FALSE;

			/* enabled */
			if (g_key_file_has_key(key_file, groups[i], "enabled", &error))
				if_conf->enabled = g_key_file_get_boolean(key_file, groups[i], "enabled", &error);
			else 
				if_conf->enabled = FALSE;

			/* debug */
			if (g_key_file_has_key(key_file, groups[i], "debug", &error))
				if_conf->debug = g_key_file_get_boolean(key_file, groups[i], "debug", &error);
			else
				if_conf->debug = FALSE;

			/* verbose */
			if (g_key_file_has_key(key_file, groups[i], "verbose", &error))
				if_conf->verbose = g_key_file_get_boolean(key_file, groups[i], "verbose", &error);
			else
				if_conf->verbose = false;

			/* insert in to hash table */
			g_hash_table_insert(conf.interface, &if_conf->if_index, if_conf);

			/* network */
			string_list = g_key_file_get_string_list(key_file, groups[i], "network", &list_len, &error);
			if (string_list)
			{
				struct in_addr addr;
				
				for (int i = 0; i < list_len; i++)
				{
					cidr_t *cidr = g_malloc0(sizeof(cidr_t));
					char *tmp = strtok(string_list[i], "/ ");
					/* IP */
					if (!inet_pton(AF_INET, tmp, &addr))
						print_and_exit("Incorrect ip format: %s\n", tmp);
					tmp = strtok(NULL, "/ ");
					/* Netmask */
					cidr->netmask = atoi(tmp);
					cidr->value = ntohl(addr.s_addr) & (0xffffffff << (32 - cidr->netmask));
					if_conf->cidr = g_list_prepend(if_conf->cidr, cidr);
				}
			}
			else
				print_and_exit("No network definition found: %s\n", error->message);
			g_strfreev(string_list);

			/* sponge */
			string_list = g_key_file_get_string_list(key_file, groups[i], "sponge", &list_len, &error);
			if (string_list)
			{
				for (int i = 0; i < list_len; i++)
				{
					if (strcmp(string_list[i], "reply") == 0)
						if_conf->sponge |= TYPE_REPLY;
					else if (strcmp(string_list[i], "request") == 0)
						if_conf->sponge |= TYPE_REQUEST;
					else if (strcmp(string_list[i], "gratuitous") == 0)
						if_conf->sponge |= TYPE_GRATUITOUS;
					else if (strcmp(string_list[i], "all") == 0)
						if_conf->sponge = TYPE_ALL; 
					else if (strcmp(string_list[i], "none") == 0)
						if_conf->sponge = TYPE_NONE;
					else
						if (string_list[i])
							print_and_exit("Unknown sponge mode: %s\n", string_list[i]);
				}
			}
			g_strfreev(string_list);
		}
	}
	g_strfreev(groups);
	g_key_file_free(key_file);
}

int main(int argc, char **argv)
{
	/* Set up libbpf logging callback */
	libbpf_set_print(libbpf_print_fn);
	GList *list, *list_head;
	int err;
	char errmsg[1024];
	char *filename = "bobby.conf";

	int c;
	while(1)
	{
		static struct option long_options[] = 
		{
			{"help", no_argument, 0, 'h'},
			{"config", required_argument, 0, 'c'},
			{0, 0, 0, 0}
		};

		int option_index = 0;

		c = getopt_long (argc, argv, "hc:", long_options, &option_index);

		if (c == -1)
			break;

		switch (c)
		{
			case 'h':
				/* print help */
				break;
			case 'c':
				if (access(optarg, F_OK) != 0)
					print_and_exit("File '%s' doesn't exist.\n", optarg);
				filename = optarg;
				break;
			default:
				print_and_exit("Unknown option error...\n");
		}
	}

	conf.store = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, g_free);
	if (!conf.store)
		print_and_exit("Unable to allocate storage, bailing.\n");

	conf.interface = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, g_free);
	if (!conf.interface)
		print_and_exit("Unable to allocate interface structure, bailing.\n");

	load_conf(filename);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	conf.sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (conf.sock < 0)
		print_and_exit("Failed to open RAW socket, bailing.\n");

	struct bobby_bpf *skel = NULL;
	skel = bobby_bpf__open_and_load();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton!\n");
		return 1;
	}

	/* Listen to the interfaces */
	list_head = g_hash_table_get_keys(conf.interface);
	for (list = list_head; list != NULL; list = list->next)
	{
		err = bpf_xdp_attach(*(u_int32_t *)list->data, bpf_program__fd(skel->progs.xdp_prog), XDP_MODE_UNSPEC, 0);
		if (err)
		{
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Failed to attach XDP program: %s\n", errmsg);
			goto cleanup;
		}
	}
	g_list_free(list_head);

	/* Set up ring buffer polling */
	struct ring_buffer *rb = NULL;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),  handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	if (conf.status_timer > 0)
	{
		printf("Status timer started with %us\n", conf.status_timer);
		status_timer = g_timer_new();
	}

	printf("Successfully started! Please Ctrl+C to stop.\n");

	/* Process events */
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
		if (status_timer && (int)g_timer_elapsed(status_timer, NULL) >= conf.status_timer)
		{
			struct tm *tm;
			char ts[100];
			time_t t;

			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%c", tm);

			/* print statistics */
			printf("[%-2s] requests: %lu (%2.1f/s), replies: %lu (%2.1f/s), total size: %i\n", ts,
					stats.requests, (float)stats.requests/conf.status_timer,
					stats.replies, (float)stats.replies/conf.status_timer,
					g_hash_table_size(conf.store));
			stats.requests = 0;
			stats.replies = 0;
			/* restart timer */
			g_timer_start(status_timer);
		}
	}

cleanup:
	close(conf.sock);

	g_timer_destroy(status_timer);

	/* Detach xdp program */
	list_head = g_hash_table_get_keys(conf.interface);
	for (list = list_head; list != NULL; list = list->next)
		bpf_xdp_detach(*(u_int32_t *)list->data, 0, 0);
	g_list_free(list_head);

	bobby_bpf__destroy(skel);

	list_head = g_hash_table_get_values(conf.interface);
	for (list = list_head; list != NULL; list = list->next)
	{
		if_conf_t *if_conf = list->data;
		g_free(if_conf->name);
		g_list_free_full(if_conf->cidr, g_free);
	}
	g_list_free(list_head);

	/* Free resources */
	ring_buffer__free(rb);

	fprintf(stderr, "Hashtable size was: %u\n", g_hash_table_size(conf.store));

	g_hash_table_remove_all(conf.store);
	g_hash_table_unref(conf.store);
	g_hash_table_remove_all(conf.interface);
	g_hash_table_unref(conf.interface);
	
	return err < 0 ? -err : 0;
}
