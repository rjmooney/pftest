/* $OpenBSD$ */

/*
 * Copyright (c) 2002 Robert Mooney.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/pfvar.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#ifdef INET6
#include <netinet/icmp6.h>
#endif
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>

#include "pfctl_parser.h"

__dead static void	usage(void);
static int		pf_match_addr(u_int8_t, struct pf_addr *, struct pf_addr *,
			    struct pf_addr *, int);
static int		pf_match_port(u_int8_t, u_int16_t, u_int16_t, u_int16_t);
static void		pf_calc_skip_steps(struct pf_rulequeue *);
static void		pftest_show_rules(void);
static int		pftest_rules(char *);
static int		pftest_test_tcp(int, char *, struct pf_pdesc *);
static int		pftest_test_udp(int, char *, struct pf_pdesc *);
static int		pftest_test_icmp(int, char *, struct pf_pdesc *);
static int		pftest_getservnumber(const char *, const char *, u_int16_t *); 
static int		pftest_geticmptype(u_int8_t, const char *, u_int8_t *);
static int		pftest_geticmpcode(u_int8_t, const char *, u_int8_t, u_int8_t *);
static int		pftest_test(void);

struct pf_rulequeue 	pf_rules;
int			opts = 0;
u_int8_t		debug = 0;
char			*infile;

#define PFTEST_HELP 								\
"Commands: [show|help|quit]\n" 							\
"Syntax  : in|out on <if> tcp|udp|icmp|icmp6 <src[,port]> <dst[,port]>\n" 	\
"        :     [FSRPAU | icmp-type <type> [icmp-code <code>]]\n"

/* callbacks for rule/nat/rdr */

int
pfctl_add_rule(struct pfctl *pf, struct pf_rule *r)
{
	static u_int16_t count = 0;
	struct pf_rule *_r;
	_r = (struct pf_rule *) malloc(sizeof(struct pf_rule));
	if (_r == NULL) return 1;

	memcpy(_r, r, sizeof(struct pf_rule));
	_r->nr = count++;
	TAILQ_INSERT_TAIL(&pf_rules, _r, entries);
	return 0;
}

int
pfctl_add_nat(struct pfctl *pf, struct pf_nat *n)
{
	fprintf(stderr, "nat is not supported: skipping rule\n");
        return 0;
}

int
pfctl_add_binat(struct pfctl *pf, struct pf_binat *b)
{
	fprintf(stderr, "binat is not supported: skipping rule\n");
        return 0;
}

int
pfctl_add_rdr(struct pfctl *pf, struct pf_rdr *r)
{
	fprintf(stderr, "rdr is not supported: skipping rule\n");
        return 0;
}

/* module specific stuff */

static void
usage()
{
	extern char *__progname;
	fprintf(stderr, "usage: %s [-qx] -R file\n", __progname);
	exit(1);
}

static int
pf_match_addr(u_int8_t n, struct pf_addr *a, struct pf_addr *m,
    struct pf_addr *b, int af)
{
        int match = 0;
        switch (af) {
        case AF_INET:
                if ((a->addr32[0] & m->addr32[0]) ==
                    (b->addr32[0] & m->addr32[0]))
                        match++;
                break;
#ifdef INET6
        case AF_INET6: 
                if (((a->addr32[0] & m->addr32[0]) ==
                     (b->addr32[0] & m->addr32[0])) &&
                    ((a->addr32[1] & m->addr32[1]) ==
                     (b->addr32[1] & m->addr32[1])) &&
                    ((a->addr32[2] & m->addr32[2]) ==
                     (b->addr32[2] & m->addr32[2])) &&
                    ((a->addr32[3] & m->addr32[3]) ==
                     (b->addr32[3] & m->addr32[3])))
                        match++;
                break;
#endif /* INET6 */
        }
        if (match) {
                if (n)
                        return (0);
                else
                        return (1);
        } else {
                if (n)
                        return (1);
                else
                        return (0);
        }
}
 
static int
pf_match_port(u_int8_t op, u_int16_t a1, u_int16_t a2, u_int16_t p)
{
        NTOHS(a1);   
        NTOHS(a2);
        NTOHS(p);
        switch (op) {
        case PF_OP_IRG:
                return (p > a1) && (p < a2);
        case PF_OP_XRG:
                return (p < a1) || (p > a2);
        case PF_OP_EQ:
                return (p == a1);
        case PF_OP_NE:
                return (p != a1);
        case PF_OP_LT:
                return (p < a1);
        case PF_OP_LE:
                return (p <= a1);
        case PF_OP_GT:
                return (p > a1);
        case PF_OP_GE:
                return (p >= a1);
        }
        return (0); /* never reached */
}

#define	PF_CALC_SKIP_STEP(i, c) do {				\
	if (a & 1 << i) { 					\
		if (c) 						\
			r->skip[i] = TAILQ_NEXT(s, entries); 	\
		else 						\
			a ^= 1 << i; 				\
	} 							\
} while (0)
                         
static void
pf_calc_skip_steps(struct pf_rulequeue *rules)
{
        struct pf_rule *r, *s;
        int a, i;
                        
        r = TAILQ_FIRST(rules);
        while (r != NULL) {
                a = 0;                  
                for (i = 0; i < PF_SKIP_COUNT; ++i) {
                        a |= 1 << i;
                        r->skip[i] = TAILQ_NEXT(r, entries);
                }
                s = TAILQ_NEXT(r, entries);
                while (a && s != NULL) {
/* 			PF_CALC_SKIP_STEP(PF_SKIP_IFP, s->ifp == r->ifp); */
			PF_CALC_SKIP_STEP(PF_SKIP_IFP, !strcmp(s->ifname, r->ifname));
                        PF_CALC_SKIP_STEP(PF_SKIP_AF, s->af == r->af);
                        PF_CALC_SKIP_STEP(PF_SKIP_PROTO, s->proto == r->proto);
                        PF_CALC_SKIP_STEP(PF_SKIP_SRC_ADDR,
                            PF_AEQ(&s->src.addr, &r->src.addr, r->af) &&
                            PF_AEQ(&s->src.mask, &r->src.mask, r->af) &&
                            s->src.not == r->src.not);
                        PF_CALC_SKIP_STEP(PF_SKIP_SRC_PORT,
                            s->src.port[0] == r->src.port[0] &&
                            s->src.port[1] == r->src.port[1] &&
                            s->src.port_op == r->src.port_op);
                        PF_CALC_SKIP_STEP(PF_SKIP_DST_ADDR,
                            PF_AEQ(&s->dst.addr, &r->dst.addr, r->af) &&
                            PF_AEQ(&s->dst.mask, &r->dst.mask, r->af) &&
                            s->dst.not == r->dst.not);
                        PF_CALC_SKIP_STEP(PF_SKIP_DST_PORT,
                            s->dst.port[0] == r->dst.port[0] &&
                            s->dst.port[1] == r->dst.port[1] &&
                            s->dst.port_op == r->dst.port_op);
                        s = TAILQ_NEXT(s, entries);
                }
                r = TAILQ_NEXT(r, entries);
        }
}

static void
pftest_show_rules(void)
{
	struct pf_rule *r;
	for (r = TAILQ_FIRST(&pf_rules); r; r = TAILQ_NEXT(r, entries))
		print_rule(r);
}

static int
pftest_rules(char *filename)
{
	struct 	pfioc_rule pr;
	struct 	pfctl pf;
	FILE 	*fin;

	fin = fopen(filename, "r");
	infile = filename;

	if (fin == NULL)
		err(1, "%s", filename);

	/* fill in callback data */
	pf.dev = -1;
	pf.opts = opts;
	pf.prule = &pr;

	TAILQ_INIT(&pf_rules);

	if (parse_rules(fin, &pf) < 0)
		errx(1, "syntax error in rule file: pf rules not loaded");
	pf_calc_skip_steps(&pf_rules);

	if (fin != stdin)
		fclose(fin);
	return (0);
}

static int
pftest_test_tcp(int direction, char *ifn, struct pf_pdesc *pd)
{
	struct		pf_addr *saddr = pd->src, *daddr = pd->dst;
	struct		tcphdr *th = pd->hdr.tcp;
	struct		pf_rule *r, *rm = NULL;
	u_int16_t	af = pd->af;

	r = TAILQ_FIRST(&pf_rules);
        while (r != NULL) {
                if (r->action == PF_SCRUB) {
                        r = TAILQ_NEXT(r, entries);
                        continue; 
                }

		if (debug)  fprintf(stderr,"current rule: %d\n", r->nr);

/*                if (r->ifp != NULL && r->ifp != ifp) */
		if (r->ifname[0] != 0 && strcmp(r->ifname, ifn) != 0) {
			if (debug) fprintf(stderr, "skipping due to interface\n");
                        r = r->skip[PF_SKIP_IFP];

		} else if (r->af && r->af != af) {
			if (debug) fprintf(stderr, "skipping due to af\n");
                        r = r->skip[PF_SKIP_AF];

		} else if (r->proto && r->proto != IPPROTO_TCP) {
			if (debug) fprintf(stderr, "skipping due to proto\n");
                        r = r->skip[PF_SKIP_PROTO];

		} else if (!PF_AZERO(&r->src.mask, af) && !PF_MATCHA(r->src.not,
                    &r->src.addr, &r->src.mask, saddr, af)) {
			if (debug) fprintf(stderr, "skipping due to saddr\n");
                        r = r->skip[PF_SKIP_SRC_ADDR];

		} else if (r->src.port_op && !pf_match_port(r->src.port_op,
                    r->src.port[0], r->src.port[1], th->th_sport)) {
			if (debug) fprintf(stderr, "skipping due to sport\n");
                        r = r->skip[PF_SKIP_SRC_PORT];

		} else if (!PF_AZERO(&r->dst.mask, af) && !PF_MATCHA(r->dst.not,
                    &r->dst.addr, &r->dst.mask, daddr, af)) {
			if (debug) fprintf(stderr, "skipping due to daddr\n");
                        r = r->skip[PF_SKIP_DST_ADDR]; 

		} else if (r->dst.port_op && !pf_match_port(r->dst.port_op,
                    r->dst.port[0], r->dst.port[1], th->th_dport)) {
			if (debug) fprintf(stderr, "skipping due to dport\n");
                        r = r->skip[PF_SKIP_DST_PORT];

		} else if (r->direction != direction) {
			if (debug) fprintf(stderr, "skipping due to direction\n");
                        r = TAILQ_NEXT(r, entries);

		} else if ((r->flagset & th->th_flags) != r->flags) {
			if (debug) fprintf(stderr, "skipping due to flags: " 
			    "(r->flagset: %d & r->flags: %d) != th->th_flags: %d\n",
			    r->flagset, r->flags, th->th_flags);
                        r = TAILQ_NEXT(r, entries);

		} else {
			if (debug)  fprintf(stderr, "matched rule %d\n", r->nr);
                        rm = r;
                        if (rm->quick)
                                break;
                        r = TAILQ_NEXT(r, entries);
                }
        }
	return rm ? rm->action : PF_PASS;
}

static int
pftest_test_udp(int direction, char *ifn, struct pf_pdesc *pd)
{
	struct		pf_addr *saddr = pd->src, *daddr = pd->dst;
	struct		udphdr *uh = pd->hdr.udp;
	struct		pf_rule *r, *rm = NULL;
	u_int16_t 	af = pd->af;

        r = TAILQ_FIRST(&pf_rules);
        while (r != NULL) {
                if (r->action == PF_SCRUB) {
                        r = TAILQ_NEXT(r, entries);
                        continue;
                }

		if (debug)  fprintf(stderr, "current rule: %d\n", r->nr);

/*                if (r->ifp != NULL && r->ifp != ifp) */
		if (r->ifname[0] != 0 && strcmp(r->ifname, ifn) != 0) {
		 	if (debug) fprintf(stderr, "skipping due to interface\n");
                        r = r->skip[PF_SKIP_IFP];

		} else if (r->af && r->af != af) {
			if (debug) fprintf(stderr, "skipping due to af\n");
                        r = r->skip[PF_SKIP_AF];

		} else if (r->proto && r->proto != IPPROTO_UDP) {
			if (debug) fprintf(stderr, "skipping due to protocol\n");
                        r = r->skip[PF_SKIP_PROTO];

		} else if (!PF_AZERO(&r->src.mask, af) &&
                    !PF_MATCHA(r->src.not, &r->src.addr, &r->src.mask,
                    saddr, af)) {
			if (debug) fprintf(stderr, "skipping due to saddr\n");
                        r = r->skip[PF_SKIP_SRC_ADDR];

		} else if (r->src.port_op && !pf_match_port(r->src.port_op,
                    r->src.port[0], r->src.port[1], uh->uh_sport)) {
			if (debug) fprintf(stderr, "skipping due to sport\n");
                        r = r->skip[PF_SKIP_SRC_PORT];

		} else if (!PF_AZERO(&r->dst.mask, af) &&
                    !PF_MATCHA(r->dst.not, &r->dst.addr, &r->dst.mask,
                        daddr, af)) {
			if (debug) fprintf(stderr, "skipping due to daddr\n");
                        r = r->skip[PF_SKIP_DST_ADDR];

		} else if (r->dst.port_op && !pf_match_port(r->dst.port_op,
                    r->dst.port[0], r->dst.port[1], uh->uh_dport)) {
			if (debug) fprintf(stderr, "skipping due to dport\n");
                        r = r->skip[PF_SKIP_DST_PORT];

		} else if (r->direction != direction) {
			if (debug) fprintf(stderr, "skipping due to direction\n");
                        r = TAILQ_NEXT(r, entries);

		} else {
			if (debug) fprintf(stderr, "matched rule %d\n", r->nr);
                        rm = r;
                        if (rm->quick)
                                break;
                        r = TAILQ_NEXT(r, entries);
                }
        }
	return rm ? rm->action : PF_PASS;
}

static int
pftest_test_icmp(int direction, char *ifn, struct pf_pdesc *pd)
{
	struct		pf_addr *saddr = pd->src, *daddr = pd->dst;
	struct		pf_rule *r, *rm = NULL;
	u_int16_t	af = pd->af;
        u_int8_t	icmptype = 0, icmpcode = 0;

        switch (pd->proto) {
        case IPPROTO_ICMP:
                icmptype = pd->hdr.icmp->icmp_type;
                icmpcode = pd->hdr.icmp->icmp_code;
                break;
#ifdef INET6
        case IPPROTO_ICMPV6:
                icmptype = pd->hdr.icmp6->icmp6_type;
                icmpcode = pd->hdr.icmp6->icmp6_code;
                break;
#endif /* INET6 */    
	default:
		return -1;
        }

        r = TAILQ_FIRST(&pf_rules);
        while (r != NULL) {
                if (r->action == PF_SCRUB) {
                        r = TAILQ_NEXT(r, entries);
                        continue;
                }

		if (debug) fprintf(stderr,"current rule: %d\n", r->nr);

/*                if (r->ifp != NULL && r->ifp != ifp) */
		if (r->ifname[0] != 0 && strcmp(r->ifname, ifn) != 0) {
			if (debug) fprintf(stderr, "skipping due to interface "
			    " (1)\n");
                        r = r->skip[PF_SKIP_IFP];   

		} else if (r->af && r->af != af) {
			if (debug) fprintf(stderr, "skipping due to af: "
			    "r->af: %d != af: %d\n", r->af, af);
                        r = r->skip[PF_SKIP_AF];

		} else if (r->proto && r->proto != pd->proto) {
			if (debug) fprintf(stderr, "skipping due to proto\n");
                        r = r->skip[PF_SKIP_PROTO];

		} else if (!PF_AZERO(&r->src.mask, af) && !PF_MATCHA(r->src.not,
                    &r->src.addr, &r->src.mask, saddr, af)) {
			if (debug) fprintf(stderr, "skipping due to saddr\n");
                        r = r->skip[PF_SKIP_SRC_ADDR];

		} else if (!PF_AZERO(&r->dst.mask, af) && !PF_MATCHA(r->dst.not,
                    &r->dst.addr, &r->dst.mask, daddr, af)) {
			if (debug) fprintf(stderr, "skipping due to daddr\n");
                        r = r->skip[PF_SKIP_DST_ADDR];

		} else if (r->direction != direction) {
			if (debug) fprintf(stderr, "skipping due to direction\n");
                        r = TAILQ_NEXT(r, entries);

/*                else if (r->ifp != NULL && r->ifp != ifp) */
		} else if (r->ifname[0] != 0 && strcmp(r->ifname, ifn) != 0) { 
			if (debug) fprintf(stderr, "skipping due to interface"
			    " (2)\n");
                        r = TAILQ_NEXT(r, entries);

		} else if (r->type && r->type != icmptype + 1) {
			if (debug) fprintf(stderr, "skipping due to icmptype:"
			    " r->type: %d != type: %d\n", r->type, icmptype);
                        r = TAILQ_NEXT(r, entries);

		} else if (r->code && r->code != icmpcode + 1) {
			if (debug) fprintf(stderr, "skipping due to icmpcode\n");
                        r = TAILQ_NEXT(r, entries);

		} else {  
			if (debug) fprintf(stderr, "matched rule %d\n", r->nr);
                        rm = r;
                        if (rm->quick) 
                                break;
                        r = TAILQ_NEXT(r, entries);
                }
        }
	return rm ? rm->action : PF_PASS;
}

static int
pftest_getservnumber(const char *token, const char *proto, u_int16_t *port)
{
	u_long	ulval;
	char 	*ep;

	if (token == NULL || proto == NULL || port == NULL) return EINVAL;
	*port = 0;

	errno = 0;
	ulval = strtoul(token, &ep, 10);
	if (*ep != 0) { /* not a number */
		struct servent *s;
		if ((s = getservbyname(token, proto)) == NULL)
			return ENOENT;
		ulval = (u_long)ntohs((u_short)s->s_port);

	} else if ((errno = ERANGE && ulval == ULONG_MAX))
		return ERANGE;

	/* port limits */
	if (ulval < 1 || ulval > 65535)
		return ERANGE;

	*port = htons((u_int16_t)ulval);
	return 0;
}

static int
pftest_geticmptype(u_int8_t af, const char *s, u_int8_t *type)
{
	u_long	ulval;
	char	*ep;

	if (s == NULL || type == NULL) return EINVAL;
	*type = 0;

	/* icmp-type */
	if (s[0] == 0) ulval = 0;
	else {
		errno = 0;
		ulval = strtoul(s, &ep, 10);
		if (*ep != 0) {	/* not a number */
			struct icmptypeent *p;
			if ((p = geticmptypebyname((char *)s, af)) == NULL)
				return ENOENT;
			ulval = p->type;

		} else if (errno == ERANGE && ulval == ULONG_MAX)
			return ERANGE;
	}

	*type = (u_int8_t) ulval;
	return 0;
}

static int
pftest_geticmpcode(u_int8_t af, const char *s, u_int8_t type, u_int8_t *code)
{
	u_long	ulval;
	char	*ep;

	if (s == NULL || code == NULL) return EINVAL;
	*code = 0;

	/* icmp-code */
	if (s[0] == 0) ulval = 0;
	else {
		errno = 0;
		ulval = strtoul(s, &ep, 10);
		if (*ep != 0) { /* not a number */
			struct icmpcodeent *p;
			if ((p = geticmpcodebyname(type, (char *)s, af)) 
			    == NULL)
				return ENOENT;
			ulval = p->code;

		} else if (errno == ERANGE && ulval == ULONG_MAX)
			return ERANGE;
	}

	*code = (u_int8_t) ulval;
	return 0;
}

static int
pftest_test(void)
{
	struct 	pf_pdesc pd;
 	struct 	pf_addr *psrc, *pdst, *phdr;
	int 	result, direction;
	char 	line[512], *p;
	char 	zdirection[10], zinterface[20], zprotocol[10];
	char 	zsource[36], zdest[36], zflags[7], zicmp_type[50];
	char	zicmp_code[50];
	char 	*token, *running;

	psrc = (struct pf_addr *) malloc(sizeof(struct pf_addr));
	pdst = (struct pf_addr *) malloc(sizeof(struct pf_addr));
	phdr = malloc(50); /* XXX enough space for all headers? */

	if ((opts & PF_OPT_QUIET) == 0)
		fprintf(stderr, PFTEST_HELP);

	while (fgets(line, sizeof(line), stdin)) {
		p = strchr(line, '\n'); if (p) *p = 0;
		p = strchr(line, '\r'); if (p) *p = 0;

		/* skip blank lines and comments */
		if (strlen(line) == '\0' || line[0] == '#')
			continue;

		/* interpreter commands */
		if (!strncmp(line, "show", 4)) {
			pftest_show_rules();
			continue;
		}
		if (!strncmp(line, "help", 4) || line[0] == '?') {
			fprintf(stderr, PFTEST_HELP);
			continue;
		}
		if (!strncmp(line, "quit", 4))
			break;

		memset(&pd, 0, sizeof(pd));
		memset(psrc, 0, sizeof(struct pf_addr));
		memset(pdst, 0, sizeof(struct pf_addr));
		memset(phdr, 0, 50); /* XXX */

		pd.src = psrc;
		pd.dst = pdst;
		pd.hdr.any = phdr;

		memset(&zdirection, 0, sizeof(zdirection));
		memset(&zinterface, 0, sizeof(zinterface));
		memset(&zprotocol, 0, sizeof(zprotocol));
		memset(&zsource, 0, sizeof(zsource));
		memset(&zdest, 0, sizeof(zdest));
		memset(&zflags, 0, sizeof(zflags));
		memset(&zicmp_type, 0, sizeof(zicmp_type));
		memset(&zicmp_code, 0, sizeof(zicmp_code));

		/* parse the user input */
		result = sscanf(line, "%9s on %9s %9s %35s %35s icmp-type %49s icmp-code %49s", 
				zdirection, zinterface, zprotocol, zsource, 
				zdest, zicmp_type, zicmp_code);
		if (result < 6) {
			result = sscanf(line, "%9s on %9s %9s %35s %35s %6[][FSRPAU]", 
					zdirection, zinterface, zprotocol, 
					zsource, zdest, zflags);
			if (result < 5) {
				warnx("Invalid format.");
				continue;
			}
		}

		/* direction */
		if (!strcmp(zdirection, "in")) direction = PF_IN;
		else if (!strcmp(zdirection, "out")) direction = PF_OUT;
		else { 
			warnx("Invalid direction.");
			continue;
		}

		/* protocol */
		if (!strcmp(zprotocol, "tcp")) pd.proto = IPPROTO_TCP;
		else if (!strcmp(zprotocol, "udp")) pd.proto = IPPROTO_UDP;
		else if (!strcmp(zprotocol, "icmp")) pd.proto = IPPROTO_ICMP;
		else if (!strcmp(zprotocol, "icmp6")) pd.proto = IPPROTO_ICMPV6;
		else { 
			warnx("Invalid protocol.");
			continue;
		}

		/* source address */
		running = zsource;
		token = strsep (&running, ",");
		if (token == NULL) { 
			warnx("Invalid source address.");
			continue;
		}

		result = inet_pton(AF_INET, token, &pd.src->pfa);
		if (result == 1) pd.af = AF_INET;
		else {
#ifdef INET6
			result = inet_pton(AF_INET6, token, &pd.src->pfa);
			if (result == 1) pd.af = AF_INET6;
			else
#endif 
			{
				warnx("Invalid source address.");
				continue;
			}
		}

#ifdef INET6
		if (pd.proto == IPPROTO_ICMPV6 && pd.af != AF_INET6) {
			warnx("ICMP6 protocol with IPv4 address.");
			continue;
		}
#endif
		/* source port */
		token = strsep(&running, ",");
		switch(pd.proto)
		{
		case IPPROTO_TCP:
			if (token) {
				result = pftest_getservnumber(token, "tcp", 
				    &pd.hdr.tcp->th_sport);
				if (result != 0) {
					warnx("Invalid source port.");
					continue;
				}
			} else {
				warnx("Source port required.");
				continue;
			}
			break;
		case IPPROTO_UDP:
			if (token) {
				result = pftest_getservnumber(token, "udp", 
				    &pd.hdr.udp->uh_sport);
				if (result != 0) {
					warnx("Invalid source port.");
					continue;
				}
			} else {
				warnx("Source port required.");
				continue;
			}
		default:
			break;
		}


		/* destination address */
		running = zdest;
		token = strsep(&running, ",");
		if (token == NULL) {
			warnx("Invalid destination address.");
			continue;
		}
		result = inet_pton(pd.af, token, &pd.dst->pfa);
		if (result != 1) {
			warnx("Invalid destination address.");
			continue;
		}

		/* destination port */
		token = strsep(&running, ",");
		switch(pd.proto)
		{
		case IPPROTO_TCP:
			if (token) {
				result = pftest_getservnumber(token, "tcp", 
				    &pd.hdr.tcp->th_dport);
				if (result != 0) {
					warnx("Invalid destination port.");
					continue;
				}
			} else {
				warnx("Destination port required.");
				continue;
			}
			break;
		case IPPROTO_UDP:
			if (token) {
				result = pftest_getservnumber(token, "udp", 
				    &pd.hdr.udp->uh_dport);
				if (result != 0) {
					warnx("Invalid destination port.");
					continue;
				}
			} else {
				warnx("Destination port required.");
				continue;
			}
		default:
			break;
		}

		/* icmp type, tcp flags */
		switch(pd.proto)
		{
		case IPPROTO_ICMP:
			result = pftest_geticmptype(AF_INET, zicmp_type, 
			    &pd.hdr.icmp->icmp_type);
			if (result != 0)
			{
				warnx("Invalid ICMP type.");
				continue;
			}
			result = pftest_geticmpcode(AF_INET, zicmp_code,
			    pd.hdr.icmp->icmp_type, &pd.hdr.icmp->icmp_code);
			if (result != 0)
			{
				warnx("Invalid ICMP code.");
				continue;
			}
			break;
#ifdef INET6
		case IPPROTO_ICMPV6:
			result = pftest_geticmptype(AF_INET6, zicmp_type, 
			    &pd.hdr.icmp6->icmp6_type);
			if (result != 0)
			{
				warnx("Invalid ICMP type.");
				continue;
			}
			result = pftest_geticmpcode(AF_INET6, zicmp_code, 
			    pd.hdr.icmp6->icmp6_type, 
			    &pd.hdr.icmp6->icmp6_code);
			if (result != 0)
			{
				warnx("Invalid ICMP code.");
				continue;
			}
			break;
#endif
		case IPPROTO_TCP: {
			int f = parse_flags(zflags);
			if (f < 0) {
				warnx("Invalid TCP flags.");
				continue;
			}
			pd.hdr.tcp->th_flags = f;
			break;
		}
		default:
			break;
		}

		/* dispatch */
		switch(pd.proto)
		{
		case IPPROTO_TCP:
			result = pftest_test_tcp(direction, zinterface, &pd);
			break;
		case IPPROTO_UDP:
			result = pftest_test_udp(direction, zinterface, &pd);
			break;
		case IPPROTO_ICMP:	/* FALLTHROUGH */
		case IPPROTO_ICMPV6:
			result = pftest_test_icmp(direction, zinterface, &pd);
			break;
		default:
			result = -1;
			warnx("Invalid protocol.");
			break;
		}

		/* pass, drop, etc */
		switch(result)
		{
		case PF_PASS:
			printf("pass: %s\n", line);
			break;
		case PF_DROP:
			printf("drop: %s\n", line);
			break;
		default:
			fprintf(stderr, "Unknown result: %d\n", result);
			break;
		}
	}

	free(psrc);
	free(pdst);
	free(phdr);

	return (0);
}

/*
 * pftest - test a packet filter rule set.  see pftest(8) for more info
 */
int
main(int argc, char *argv[])
{
	int	error = 0;
	int 	ch;
	extern 	int optind;
	extern 	char *optarg;
	char 	*rulesopt = NULL;

	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "qR:x")) != -1) {
		switch (ch) {
                case 'q':
                        opts |= PF_OPT_QUIET;
                        break;
		case 'R':
			rulesopt = optarg;
			break;
		case 'x':
			debug = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (argc != optind) {
		warnx("unknown command line argument: %s ...", argv[optind]);
		usage();
		/* NOTREACHED */
	}

	if (rulesopt == NULL)
		errx(1, "rule file must be specified");

	if (pftest_rules(rulesopt))
		error = 1;

        if (pftest_test())
		error = 1;

	exit(error);
}
