/*
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License") 1.1!
 * You may not use this file except in compliance with the License.
 *
 * See  https://spdx.org/licenses/CDDL-1.1.html  for the specific
 * language governing permissions and limitations under the License.
 *
 * Copyright 2021 Jens Elkner (jel+fstatmex-src@cs.ovgu.de)
 */
#include <getopt.h>
#include <arpa/inet.h>
#include <prom.h>
#include <sys/param.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#ifdef __linux
#include <linux/fs.h>
#endif

#include <prom.h>
#include <prom_log.h>
#include <microhttpd.h>

#ifndef VERSION
#define VERSION "0.1.0"
#endif

#define MAX_PLEN MAXPATHLEN

#define TOTAL_KEY "#overall#"		// so sort moves it to the start
 
static const char *stype[] = {
	"???", "FIFO", "CHR", "???",
	"DIR", "???", "BLK", "???",
	"REG", "???", "LNK", "???",
	"SOCK", "DOOR", "PORT", "???"
};

typedef enum {
    SMF_EXIT_OK = 0,
    SMF_EXIT_ERR_OTHER,
    SMF_EXIT_ERR_FATAL = 95,
    SMF_EXIT_ERR_CONFIG,
    SMF_EXIT_MON_DEGRADE,
    SMF_EXIT_MON_OFFLINE,
    SMF_EXIT_ERR_NOSMF,
    SMF_EXIT_ERR_PERM,
    SMF_EXIT_TEMP_DISABLE,
    SMF_EXIT_TEMP_TRANSIENT
} SMF_EXIT_CODE;

static struct option options[] = {
	{"anonym",				no_argument,		NULL, 'A'},
	{"hole-check",			no_argument,		NULL, 'C'},
	{"no-scrapetime",		no_argument,		NULL, 'L'},
	{"no-scrapetime-all",	no_argument,		NULL, 'S'},
	{"version",				no_argument,		NULL, 'V'},
	{"hole-size",			no_argument,		NULL, 'Z'},
	{"addr",				required_argument,	NULL, 'a'},
	{"compact",				no_argument,		NULL, 'c'},
	{"depth",				no_argument,		NULL, 'd'},
	{"help",				no_argument,		NULL, 'h'},
	{"label",				required_argument,	NULL, 'l'},
	{"metrics",				no_argument,		NULL, 'm'},
	{"logfile",				required_argument,	NULL, 'o'},
	{"port",				required_argument,	NULL, 'p'},
	{"show-specials",		no_argument,		NULL, 's'},
	{"verbosity",			required_argument,	NULL, 'v'},
	{0, 0, 0, 0}
};

static const char *shortUsage = {
	"[-ACLSVZchms] [-a ip] [-d depth] [-l label=value] [-p port] [-o file] [-v DEBUG|INFO|WARN|ERROR|FATAL] dir ..."
};

static struct {
	int req_seen;				// our "mutex" for starting the work
	bool shutdown;				// tell MHD-daemon to ignore requests

	bool anonym;
	bool show_specials;
	bool hole_check;
	bool hole_sz;
	bool prom_enabled;
	uint32_t promflags;
	struct MHD_Daemon *daemon;
	uint32_t port;
	struct in6_addr *addr;
	bool ipv6;
	uint32_t prom_depth;
	int MHD_error;
	char *logfile;
	char *label_name;
	char *label_value;
	prom_counter_t *req_counter;
	prom_counter_t *res_counter;
	prom_counter_t *sparse_counter;
	prom_counter_t *link_counter;
	prom_counter_t *dir_counter;
	prom_counter_t *misc_counter;
	prom_histogram_t *fsz_hist;
	prom_histogram_t *ssz_hist;
} global = {
	.req_seen = 0,
	.shutdown = false,
	.anonym = false,
	.show_specials = false,
	.hole_check = false,
	.hole_sz = false,
	.prom_enabled = false,
	.promflags = PROM_PROCESS | PROM_SCRAPETIME | PROM_SCRAPETIME_ALL,
	.daemon = NULL,
	.port = 8080,
	.addr = NULL,
	.ipv6 = false,
	.prom_depth = 4,
	.MHD_error = -1,
	.logfile = NULL,
	.label_name = NULL,
	.label_value = NULL,
	.req_counter = NULL,
	.res_counter = NULL,
	.sparse_counter = NULL,
	.link_counter = NULL,
	.dir_counter = NULL,
	.misc_counter = NULL,
	.fsz_hist = NULL,
	.ssz_hist = NULL
};

// generate the short option string for getopts from <opts>
static char *
getShortOpts(const struct option *opts) {
	int i, k = 0, len = 0;
	char *str;

	while (opts[len].name != NULL)
		len++;
	str = malloc(sizeof(char) * len  * 2 + 1);
	if (str == NULL)
		return NULL;

	str[k++] = '+';		// POSIXLY_CORRECT
	for (i = 0; i < len; i++) {
		str[k++] = opts[i].val;
		if (opts[i].has_arg == required_argument)
			str[k++] = ':';
	}
	str[k] = '\0';
	return str;
}

static int
setupProm(void) {
	static const char *keys[] = { NULL, NULL };
	prom_collector_t* pc = NULL;
	prom_counter_t *reqc, *resc, *linkc, *dirc, *miscc, *sparsec;
	prom_histogram_t *fsz_hist = NULL, *ssz_hist = NULL;
	phb_t *fbuckets = NULL, *sbuckets = NULL;
	reqc = resc = linkc = dirc = miscc = sparsec = NULL;
	int key_len = 1;

	if (pcr_init(global.promflags, "fstatmex_"))
		return 1;

	if (global.label_name != NULL) {
		keys[1] = global.label_name;
		key_len = 2;
	}

	keys[0] = "url";
	if ((global.req_counter = prom_counter_new("request_total",
		"Number of HTTP requests seen since the start of the exporter "
		"excl. the current one.",
		key_len, keys)) == NULL)
		goto fail;
	reqc = global.req_counter;
	if (pcr_register_metric(global.req_counter))
		goto fail;
	reqc = NULL;

	keys[0] = "type";
	if ((global.res_counter = prom_counter_new("response_total",
		"HTTP responses by count and bytes excl. this response and "
		"HTTP headers seen since the start of the exporter.",
		key_len, keys)) == NULL)
		goto fail;
	resc = global.res_counter;
	if (pcr_register_metric(global.res_counter))
		goto fail;
	resc = NULL;

	keys[0] = "dir";

	if ((global.sparse_counter = prom_counter_new("sparsefiles",
		"Number of sparse files beneath a directory.", key_len, keys)) == NULL)
		goto fail;
	sparsec = global.sparse_counter;
	if (pcr_register_metric(global.sparse_counter))
		goto fail;
	sparsec = NULL;

	if ((global.link_counter = prom_counter_new("links",
		"Number of links beneath a directory.", key_len, keys)) == NULL)
		goto fail;
	linkc = global.link_counter;
	if (pcr_register_metric(global.link_counter))
		goto fail;
	linkc = NULL;

	if ((global.dir_counter = prom_counter_new("dirs",
		"Number of directories beneath a directory.", key_len, keys)) == NULL)
		goto fail;
	dirc = global.dir_counter;
	if (pcr_register_metric(global.dir_counter))
		goto fail;
	dirc = NULL;

	// S_ISFIFO |S_ISCHR |S_ISBLK |S_ISBLK |S_ISSOCK |S_ISDOOR |S_ISPORT
	if ((global.misc_counter = prom_counter_new("miscs",
		"Number of directory entries beneath a directory which are neither a "
		"file, link nor direcotory, e.g. sockets, block devices, doors, etc...",
		key_len, keys)) == NULL)
		goto fail;
	miscc = global.misc_counter;
	if (pcr_register_metric(global.misc_counter))
		goto fail;
	miscc = NULL;

	if ((fbuckets = phb_exponential(512, 2, 24)) == NULL)
		goto fail;
	if ((global.fsz_hist = prom_histogram_new("file_bytes",
		"total size of files (st_size) beneath a directory in bytes.",
		fbuckets, key_len, keys)) == NULL)
		goto fail;
	fsz_hist = global.fsz_hist;
	if (pcr_register_metric(global.fsz_hist))
		goto fail;
	fsz_hist = NULL;
	
	if ((sbuckets = phb_exponential(32, 2, 30)) == NULL)
		goto fail;
	if ((global.ssz_hist = prom_histogram_new("sparse_bytes",
		"total size of holes per file of files beneath a directory in bytes.",
		sbuckets, key_len, keys)) == NULL)
		goto fail;
	ssz_hist = global.ssz_hist;
	if (pcr_register_metric(global.ssz_hist))
		goto fail;
	ssz_hist = NULL;

	return 0;

fail:
	if (pc != NULL)
		prom_collector_destroy(pc);
	if (reqc != NULL)
		prom_counter_destroy(reqc);
	if (resc != NULL)
		prom_counter_destroy(resc);
	if (sparsec != NULL)
		prom_counter_destroy(sparsec);
	if (linkc != NULL)
		prom_counter_destroy(linkc);
	if (dirc != NULL)
		prom_counter_destroy(dirc);
	if (miscc != NULL)
		prom_counter_destroy(miscc);
	if (fsz_hist != NULL)
		prom_histogram_destroy(fsz_hist);
	else if (fbuckets != NULL)
		phb_destroy(fbuckets);
	if (ssz_hist != NULL)
		prom_histogram_destroy(ssz_hist);
	else if (sbuckets != NULL)
		phb_destroy(sbuckets);

	global.req_counter = global.res_counter = NULL;
	pcr_destroy(PROM_COLLECTOR_REGISTRY);

	return 1;
}

static void
cleanupProm(void) {
	pcr_destroy(PROM_COLLECTOR_REGISTRY);
	global.req_counter = global.res_counter = NULL;
}

// redirect MHD_DLOG to prom_log
static void
MHD_logger(void *cls, const char *fmt, va_list ap) {
	static char s[256];

	// the experimental API has loglevel decision support, but it is usually n/a
	(void) cls;		// unused
	vsnprintf(s, sizeof(s), fmt, ap);
	// since MHD does not return error details but usually logs the reason for
	// an error before polluting errno again, we capture it here. At least for
	// MHD_start_daemon() it should be sufficient.
	global.MHD_error = errno;
	prom_log(PLL_WARN, (const char*) s);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static int
http_handler(void *cls, struct MHD_Connection *connection, const char *url,
	const char *method, const char *version, const char *upload_data,
	size_t *upload_data_size, void **con_cls)
{
#pragma GCC diagnostic pop
	char *body;
	size_t len;
	struct MHD_Response *response;
	enum MHD_ResponseMemoryMode mode = MHD_RESPMEM_PERSISTENT;
	unsigned int status = MHD_HTTP_BAD_REQUEST;
	static const char *labels[] = { "" };
	static char *RESP[] = { NULL, NULL, NULL, NULL };
	static int rlen[] = { 0, 0, 0, 0 };

	int ret;

	if (RESP[0] == NULL) {
		RESP[0]= prom_strdup("Invalid HTTP Method\n");
		rlen[0] = strlen(RESP[0]);
		RESP[1]= prom_strdup("<html><body>See <a href='/metrics'>/metrics</a>.\r\n");
		rlen[1] = strlen(RESP[1]);
		RESP[2]= prom_strdup("Bad Request\n");
		rlen[2] = strlen(RESP[2]);
		RESP[3]= prom_strdup("Shutdown in progress\n");
		rlen[3] = strlen(RESP[3]);
	}

	if (global.shutdown) {
		body = RESP[3];
		len = rlen[3];
		labels[0] = "shutdown";
		mode = MHD_HTTP_NO_RESPONSE;
	} else if (strcmp(method, "GET") != 0) {
		body = RESP[0];
		len = rlen[0];
		labels[0] = "other";
	} else if (strcmp(url, "/") == 0) {
		body = RESP[1];
		len = rlen[1];
		status = MHD_HTTP_OK;
		labels[0] = "/";
	} else if (strcmp(url, "/metrics") == 0) {
		body = pcr_bridge(PROM_COLLECTOR_REGISTRY);
		len = strlen(body);
		labels[0] = "/metrics";
		mode = MHD_RESPMEM_MUST_FREE;
		status = MHD_HTTP_OK;
	} else {
		body = RESP[2];
		len = rlen[2];
		labels[0] = "other";
	}
	prom_counter_inc(global.req_counter, labels);

	response = MHD_create_response_from_buffer(len, body, mode);
	if (response == NULL) {
		if (mode == MHD_RESPMEM_MUST_FREE)
			free(body);
		ret = MHD_NO;
	} else {
		labels[0] = "count";
		prom_counter_inc(global.res_counter, labels);
		labels[0] = "bytes";
		prom_counter_add(global.res_counter, len, labels);
		ret = MHD_queue_response(connection, status, response);
		MHD_destroy_response(response);
		global.req_seen++;
	}
	return ret;
}

static int
startHttpServer(void) {
	struct sockaddr *addr = NULL;
	uint32_t flags = MHD_USE_DEBUG;	// same as MHD_USE_ERROR_LOG but backward comp.
	// since there is no way to use a blocking, i.e. one (this) thread only
	// MHD_run(), or MHD_{e?poll|select}, or MHD_polling_thread.
	// same as MHD_USE_INTERNAL_POLLING_THREAD but backward compatible
	flags |= MHD_USE_SELECT_INTERNALLY;
	if (MHD_is_feature_supported(MHD_FEATURE_EPOLL) == MHD_YES)
		flags |= MHD_USE_EPOLL;
	else if (MHD_is_feature_supported(MHD_FEATURE_POLL) == MHD_YES)
		flags |= MHD_USE_POLL;

	if (global.addr != NULL) {
		struct sockaddr_in v4addr;
		struct sockaddr_in6 v6addr;
		size_t len;
		char buf[64];

		buf[0] = '\0';
		if (global.ipv6) {
			flags |= MHD_USE_IPv6;
			len = sizeof (struct sockaddr_in6);
			inet_ntop(AF_INET6, global.addr, buf, len);
			memset(&v6addr, 0, len);
			v6addr.sin6_family = AF_INET6;
			v6addr.sin6_port = htons (global.port);
			memcpy(&(v6addr.sin6_addr), global.addr, sizeof(struct in6_addr)); 
			addr = (struct sockaddr *) &v6addr;
		} else {
			len = sizeof (struct sockaddr_in);
			inet_ntop(AF_INET, global.addr, buf, len);
			memset(&v4addr, 0, len);
			v4addr.sin_family = AF_INET;
			v4addr.sin_port = htons (global.port);
			memcpy(&(v4addr.sin_addr), global.addr, sizeof(struct in_addr)); 
			addr = (struct sockaddr *) &v4addr;
		}
		PROM_INFO("Listening on IP%s: %s:%u", global.ipv6 ? "v6" : "v4", buf,
			global.port);
	} else {
		PROM_INFO("Listening on IPv4: 0.0.0.0:%u", global.port);
	}

	global.daemon = MHD_start_daemon(flags, global.port,
		/* checkClientFN */ NULL, /* checkClientFN arg */ NULL,
		/* requestHandler */ &http_handler, /* requestHandler arg */ NULL,
		MHD_OPTION_EXTERNAL_LOGGER, &MHD_logger, /* logstream */ NULL,
		MHD_OPTION_SOCK_ADDR, addr,
		MHD_OPTION_END);
	if (global.daemon == NULL) {
		PROM_FATAL("Unable to start http daemon.", "");
		return global.MHD_error == EACCES
			? SMF_EXIT_ERR_PERM
			: SMF_EXIT_ERR_OTHER;
	}
	return SMF_EXIT_OK;
}


static size_t
showHolesize(int fd, char *pname, off_t offset, size_t filesz) {
	size_t sz = 0;
	size_t c = 0;
	off_t newoffset;

	while (offset < (off_t) filesz) {
		c++;
		if ((newoffset = lseek(fd, offset, SEEK_DATA)) == -1) {
			if (errno == ENXIO)
				sz += filesz - offset;
			else
				perror(pname);
			offset = filesz;
		} else {
			sz += newoffset - offset;
			if ((offset = lseek(fd, newoffset, SEEK_HOLE)) == -1) {
				if (errno != ENXIO)
					perror(pname);
				offset = filesz;
			}
		}
	}

	fprintf(stdout, "SPARSE: %ld hole%s with %ld bytes in %s\n",
		c, c == 1 ? "" : "s", sz, pname);
	return sz;
}

static size_t
visit(char *path, size_t remain, uint32_t depth, size_t *sparsefiles, char *key)
{
	struct stat st;
	struct dirent *e;
	char *name, *p, *end, buf[MAX_PLEN];
	size_t len, sz = 0, t, dc = 0;
	int fd;
	off_t o;
	const char *labels[] = { key, global.label_value };
	const char *total_labels[] = { TOTAL_KEY, global.label_value };

	if (remain == 0)
		return sz;

	DIR *dir = opendir(path);

	if (dir == NULL) {
		perror(path);
		return sz;
	}

	p = end = path + MAX_PLEN - remain - 1;
	*p = '/';
	p++;
	remain--;
	while ((e = readdir(dir)) != NULL) {
		if (e->d_ino == 0)
			continue;
		name = e->d_name;
		if (*name == '.') {
			if (name[1] == 0)
				continue;
			else if (name[1] == '.' && name[2] == 0)
				continue;
		}
		len = strlen(name);
		if (remain < len) {
			PROM_WARN("Skipping too long path: %s/%s\n", path, name);
			continue;
		}
		strcpy(p, name);
		if (lstat(path, &st) == -1)
			continue;
		if (S_ISLNK(st.st_mode)) {
			if (global.prom_enabled) {
				prom_counter_inc(global.link_counter, labels);
				prom_counter_inc(global.link_counter, total_labels);
			}
			continue;
		}
		if (S_ISDIR(st.st_mode)) {
			char *newkey;
			if (depth > global.prom_depth) {
				newkey = key;
			} else if (global.anonym) {
				dc++;
				sprintf(buf, "%s/%03lx", key, dc);
				newkey = prom_strdup(buf);
			} else {
				newkey = prom_strdup(path);
			}
			if (global.prom_enabled) {
				prom_counter_inc(global.dir_counter, labels);
				prom_counter_inc(global.dir_counter, total_labels);
			}
			sz += visit(path, remain - len, depth + 1, sparsefiles, newkey);
			if (key != newkey)
				free(newkey);
		} else if (S_ISREG(st.st_mode)) {
			if (global.prom_enabled) {
				prom_histogram_observe(global.fsz_hist,st.st_size,labels);
				prom_histogram_observe(global.fsz_hist,st.st_size,total_labels);
			}
			if (global.hole_check && st.st_size > 0
				&& (fd = open(path, O_RDONLY, 0)) != -1)
			{
				if ((o = lseek(fd, 0, SEEK_HOLE)) == -1) {
					if (errno != ENXIO)
						perror(path);
				} else if (o != st.st_size) {
					(*sparsefiles)++;
					if (global.prom_enabled && !global.hole_sz) {
						// for histograms see  spares_bytes_count
						prom_counter_inc(global.sparse_counter, labels);
						prom_counter_inc(global.sparse_counter, total_labels);
					}
					if (global.hole_sz) {
						t = showHolesize(fd, path, o, st.st_size);
						sz += t;
						if (global.prom_enabled) {
							prom_histogram_observe(global.ssz_hist, t, labels);
							prom_histogram_observe(global.ssz_hist, t,
								total_labels);
						}
					} else {
						fprintf(stdout, "SPARSE: hole @%ld in %s\n", o, path);
					}
				}
				close(fd);
			}
		} else {
			// S_ISFIFO |S_ISCHR |S_ISBLK |S_ISBLK |S_ISSOCK |S_ISDOOR |S_ISPORT
			if (global.prom_enabled) {
				prom_counter_inc(global.misc_counter, labels);
				prom_counter_inc(global.misc_counter, total_labels);
			}
			if (global.show_specials) {
				fprintf(stdout,"%s: %s\n",stype[(st.st_mode >> 12) & 0xF],path);
			}
		}
	}
	closedir(dir);
	*end = '\0';
	remain++;
	return sz;
}

char *
normalizePath(char *path) {
	char *p, *s, *npath;

	if (path == NULL || path[0] == '\0')
		return NULL;

	npath = prom_strdup(path);
	p = npath + strlen(npath);

	// remove trailing slashes
	while (p != npath && *--p == '/')
		;
	if (p == npath)
		return npath;
	p[1] = '\0';

	// remove leading slashes
	s = npath;
	while (*s == '/')
		s++;
	if (s < npath + 2)
		return npath;
	p = prom_strdup(s - 1);
	free(npath); 
	return p;
}

int
checkopts(int argc, char **argv) {
	uint32_t i, err = 0;
	struct in_addr inaddr;
	struct in6_addr in6addr;
	struct in6_addr *addr = malloc(sizeof(struct in6_addr));
	char *s = getShortOpts(options), *p;

	while (1) {
		int c, optidx = 0;
		if (s == NULL)
			break;
		c = getopt_long(argc, argv, s, options, &optidx);
		if (c == -1)
			break;
		switch (c) {
			case 'A':
				global.anonym = true;
				break;
			case 'C':
				global.hole_check = true;
				break;
			case 'L':
				global.promflags &= ~PROM_SCRAPETIME;
				break;
			case 'S':
				global.promflags &= ~PROM_SCRAPETIME_ALL;
				break;
			case 'V':
				fputs("fstatmex Version " VERSION
					"\n(C) 2021 Jens Elkner "
					"(jel+fstatmex@cs.uni-magdeburg.de\n",
					stdout);
				return 0;
			case 'Z':
				global.hole_check = true;
				global.hole_sz = true;
				break;
			case 'a':
				if (strstr(optarg, ":") == NULL) {
					if ((i = inet_pton(AF_INET, optarg, &inaddr)) == 1)
						memcpy(addr, &inaddr, sizeof(struct in_addr));
				} else if ((i = inet_pton(AF_INET6, optarg, &in6addr)) == 1) {
					if (MHD_is_feature_supported(MHD_FEATURE_IPv6) == MHD_NO) {
						fprintf(stderr, "libmicrohttpd has no IPv6 support");
						i = 0;
					} else {
						memcpy(addr, &in6addr, sizeof(struct in6_addr));
						global.ipv6 = true;
					}
				}
				if (i != 1) {
					fprintf(stderr, "Invalid IP address '%s'.", optarg);
					err++;
				} else {
					global.addr = addr;
					addr = NULL;
				}
				break;
			case 'c':
				global.promflags |= PROM_COMPACT;
				break;
			case 'd':
				if ((sscanf(optarg, "%u", &i) != 1) || i > 512) {
					fprintf(stderr, "Invalid depth '%s'. Should be <= 512\n",
						optarg);
					err++;
				} else {
					global.prom_depth = i;
				}
				break;
			case 'h':
				fprintf(stderr, "Usage: %s %s\n", argv[0], shortUsage);
				return 0;
			case 'l':
				p = strchr(optarg, '=');
				if (p == NULL) {
					fprintf(stderr, "Invalid label=value pair '%s'\n", optarg);
					err++;
				} else if (strlen(p+1) == 0) {
					fprintf(stderr, "label=value pair '%s' has no value\n",
						optarg);
					err++;
				} else {
					*p = '\0';
					if (pcr_check_name(optarg, 1)) {
						fprintf(stderr, "Invalid label name '%s'\n", optarg);
						err++;
					} else if (strcmp(optarg, "le") == 0 
						|| strcmp(optarg, "dir") == 0
						|| strcmp(optarg, "quantile") == 0)
					{
						fprintf(stderr, "Invalid label name '%s' - labels 'dir'"
								" 'quantile' and 'le' are reserved\n", optarg);
						err++;
					} else {
						global.label_name = strdup(optarg);
						global.label_value = strdup(p + 1);
					}
					*p = '=';
				}
				break;
			case 'm':
				global.prom_enabled = true;
				break;
			case 'o':
				if (global.logfile != NULL)
					free(global.logfile);
				global.logfile = prom_strdup(optarg);
				break;
			case 'p':
				if ((sscanf(optarg, "%u", &i) != 1) || i == 0) {
					fprintf(stderr, "Invalid port '%s'.\n", optarg);
					err++;
				} else {
					global.port = i;
				}
				break;
			case 's':
				global.show_specials = true;
				break;
			case 'v':
				i = prom_log_level_parse(optarg);
				if (i == 0) {
					fprintf(stderr,"Invalid log level '%s'.\n",optarg);
					err++;
				} else {
					prom_log_level(i);
				}
				break;
			case '?':
				fprintf(stderr, "Usage: %s %s\n", argv[0], shortUsage);
				return(1);
		}
	}
	free(s);
	free(addr);
	return err;
}

int
main(int argc, char **argv) {
	int err, i;
	char *s;
	size_t sz = 0, sparsefiles = 0;

	if (checkopts(argc, argv))
		return SMF_EXIT_ERR_CONFIG;

	if (optind >= argc) {
		fprintf(stderr, "Usage: %s %s\n", argv[0], shortUsage);
		return 0;
	}

	if (global.logfile != NULL) {
		FILE *logfile = fopen(global.logfile, "a");
		if (logfile != NULL)
			prom_log_use(logfile);
		else {
			fprintf(stderr, "Unable to open logfile '%s': %s\n",
				global.logfile, strerror(errno));
			return (errno == EACCES) ? SMF_EXIT_ERR_PERM : SMF_EXIT_ERR_CONFIG;
		}
	}
	err = SMF_EXIT_OK;
	if (global.prom_enabled) {
		if (setupProm() != 0) {
			fprintf(stderr, "Failed to setup counters/histograms. Exiting.\n");
			return 1;
		}
		err = startHttpServer();
		if (err == SMF_EXIT_OK) {
			// wait for the first connect before starting the work
			PROM_INFO("Waiting for %d metric requests ...", 2);
			while (global.req_seen < 2)
				sleep(1);
			PROM_INFO("Starting the scanner ...", "");
		}
	}

	if (err == SMF_EXIT_OK) {
		char path[MAX_PLEN];
		struct timespec start, end;
		int r;

		r = clock_gettime(CLOCK_MONOTONIC, &start);
		for (i=optind; i < argc; i++) {
			s = normalizePath(argv[i]);
			strncpy(path, s, MAX_PLEN);
			PROM_INFO("Processing %s ...\n", path);
			sz += visit(path, MAX_PLEN - 1 - strlen(path), 1, &sparsefiles, s);
			free(s);
		}
		r += clock_gettime(CLOCK_MONOTONIC, &end);
		if (r == 0) {
			time_t t = end.tv_sec - start.tv_sec;
			long ns = end.tv_nsec - start.tv_nsec;
			double duration = t + ns * 1e-9;
			fprintf(stdout, "Scan time: %.17g s\n", duration);
		}
		if (global.hole_sz && sz > 0)
			fprintf(stdout, "Total %ld sparse files with %ld sparse bytes.\n",
				sparsefiles, sz);
		else if (global.hole_check)
			fprintf(stdout, "Total %ld sparse files.\n", sparsefiles);
		fflush(stdout);
		fflush(stderr);
	}

	if (global.prom_enabled && err == SMF_EXIT_OK) {
		// wait 5 min to make sure, everything gets fetched 
		PROM_INFO("Job done. Waiting 5 min before shutting down ...", "");
		for (i=0; i < 30; i++) {
			sleep(10);
			fprintf(stderr, ".");
		}
		fprintf(stderr, "\nShutdown initiated. Gracetime 10s ...\n");
		global.shutdown = true;
		sleep(10);	// give it some time to finish response
		MHD_stop_daemon(global.daemon);
		fprintf(stderr, "Done.\n");
		cleanupProm();
	}
	free(global.addr);
	return err;
}
