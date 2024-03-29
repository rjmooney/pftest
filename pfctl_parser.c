/*	$OpenBSD: pfctl_parser.c,v 1.60 2002/01/09 11:30:53 dhartmei Exp $ */

/*
 * Copyright (c) 2001 Daniel Hartmeier
 * All rights reserved.
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
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#define TCPSTATES
#include <netinet/tcp_fsm.h>
#include <net/pfvar.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <err.h>

#include "pfctl_parser.h"

int		 unmask (struct pf_addr *, u_int8_t);
void		 print_addr (struct pf_addr *, struct pf_addr *, u_int8_t);
void		 print_host (struct pf_state_host *, u_int8_t);
void		 print_seq (struct pf_state_peer *);
void		 print_port (u_int8_t, u_int16_t, u_int16_t, char *);
void		 print_flags (u_int8_t);

char *tcpflags = "FSRPAU";

struct icmptypeent icmp_type[] = {
	{ "echoreq",	ICMP_ECHO },
	{ "echorep",	ICMP_ECHOREPLY },
	{ "unreach",	ICMP_UNREACH },
	{ "squench",	ICMP_SOURCEQUENCH },
	{ "redir",	ICMP_REDIRECT },
	{ "althost",	ICMP_ALTHOSTADDR },
	{ "routeradv",	ICMP_ROUTERADVERT },
	{ "routersol",	ICMP_ROUTERSOLICIT },
	{ "timex",	ICMP_TIMXCEED },
	{ "paramprob",	ICMP_PARAMPROB },
	{ "timereq",	ICMP_TSTAMP },
	{ "timerep",	ICMP_TSTAMPREPLY },
	{ "inforeq",	ICMP_IREQ },
	{ "inforep",	ICMP_IREQREPLY },
	{ "maskreq",	ICMP_MASKREQ },
	{ "maskrep",	ICMP_MASKREPLY },
	{ "trace",	ICMP_TRACEROUTE },
	{ "dataconv",	ICMP_DATACONVERR },
	{ "mobredir",	ICMP_MOBILE_REDIRECT },
	{ "ipv6-where",	ICMP_IPV6_WHEREAREYOU },
	{ "ipv6-here",	ICMP_IPV6_IAMHERE },
	{ "mobregreq",	ICMP_MOBILE_REGREQUEST },
	{ "mobregrep",	ICMP_MOBILE_REGREPLY },
	{ "skip",	ICMP_SKIP },
	{ "photuris",	ICMP_PHOTURIS }

};

struct icmptypeent icmp6_type[] = {
	{ "unreach",	ICMP6_DST_UNREACH },
	{ "toobig",	ICMP6_PACKET_TOO_BIG },
	{ "timex",	ICMP6_TIME_EXCEEDED },
	{ "paramprob",	ICMP6_PARAM_PROB },
	{ "echoreq",	ICMP6_ECHO_REQUEST },
	{ "echorep",	ICMP6_ECHO_REPLY },
	{ "groupqry",	ICMP6_MEMBERSHIP_QUERY },
	{ "listqry",	MLD6_LISTENER_QUERY },
	{ "grouprep",	ICMP6_MEMBERSHIP_REPORT },
	{ "listenrep",	MLD6_LISTENER_REPORT },
	{ "groupterm",	ICMP6_MEMBERSHIP_REDUCTION },
	{ "listendone", MLD6_LISTENER_DONE },
	{ "routersol",	ND_ROUTER_SOLICIT },
	{ "routeradv",	ND_ROUTER_ADVERT },
	{ "neighbrsol", ND_NEIGHBOR_SOLICIT },
	{ "neighbradv", ND_NEIGHBOR_ADVERT },
	{ "redir",	ND_REDIRECT },
	{ "routrrenum", ICMP6_ROUTER_RENUMBERING },
	{ "wrureq",	ICMP6_WRUREQUEST },
	{ "wrurep",	ICMP6_WRUREPLY },
	{ "fqdnreq",	ICMP6_FQDN_QUERY },
	{ "fqdnrep",	ICMP6_FQDN_REPLY },
	{ "niqry",	ICMP6_NI_QUERY },
	{ "nirep",	ICMP6_NI_REPLY },
	{ "mtraceresp",	MLD6_MTRACE_RESP },
	{ "mtrace",	MLD6_MTRACE }
};
	
struct icmpcodeent icmp_code[] = {
	{ "net-unr",		ICMP_UNREACH,	ICMP_UNREACH_NET },
	{ "host-unr",		ICMP_UNREACH,	ICMP_UNREACH_HOST },
	{ "proto-unr",		ICMP_UNREACH,	ICMP_UNREACH_PROTOCOL },
	{ "port-unr",		ICMP_UNREACH,	ICMP_UNREACH_PORT },
	{ "needfrag",		ICMP_UNREACH,	ICMP_UNREACH_NEEDFRAG },
	{ "srcfail",		ICMP_UNREACH,	ICMP_UNREACH_SRCFAIL },
	{ "net-unk",		ICMP_UNREACH,	ICMP_UNREACH_NET_UNKNOWN },
	{ "host-unk",		ICMP_UNREACH,	ICMP_UNREACH_HOST_UNKNOWN },
	{ "isolate",		ICMP_UNREACH,	ICMP_UNREACH_ISOLATED },
	{ "net-prohib",		ICMP_UNREACH,	ICMP_UNREACH_NET_PROHIB },
	{ "host-prohib",	ICMP_UNREACH,	ICMP_UNREACH_HOST_PROHIB },
	{ "net-tos",		ICMP_UNREACH,	ICMP_UNREACH_TOSNET },
	{ "host-tos",		ICMP_UNREACH,	ICMP_UNREACH_TOSHOST },
	{ "filter-prohib",	ICMP_UNREACH,	ICMP_UNREACH_FILTER_PROHIB },
	{ "host-preced",	ICMP_UNREACH,	ICMP_UNREACH_HOST_PRECEDENCE },
	{ "cutoff-preced",	ICMP_UNREACH,	ICMP_UNREACH_PRECEDENCE_CUTOFF },
	{ "redir-net",		ICMP_REDIRECT,	ICMP_REDIRECT_NET },
	{ "redir-host",		ICMP_REDIRECT,	ICMP_REDIRECT_HOST },
	{ "redir-tos-net",	ICMP_REDIRECT,	ICMP_REDIRECT_TOSNET },
	{ "redir-tos-host",	ICMP_REDIRECT,	ICMP_REDIRECT_TOSHOST },
	{ "normal-adv",		ICMP_ROUTERADVERT, ICMP_ROUTERADVERT_NORMAL },
	{ "common-adv",		ICMP_ROUTERADVERT, ICMP_ROUTERADVERT_NOROUTE_COMMON },
	{ "transit",		ICMP_TIMXCEED,	ICMP_TIMXCEED_INTRANS },
	{ "reassemb",		ICMP_TIMXCEED,	ICMP_TIMXCEED_REASS },
	{ "badhead",		ICMP_PARAMPROB,	ICMP_PARAMPROB_ERRATPTR },
	{ "optmiss",		ICMP_PARAMPROB,	ICMP_PARAMPROB_OPTABSENT },
	{ "badlen",		ICMP_PARAMPROB,	ICMP_PARAMPROB_LENGTH },
	{ "unknown-ind",	ICMP_PHOTURIS,	ICMP_PHOTURIS_UNKNOWN_INDEX },
	{ "auth-fail",		ICMP_PHOTURIS,	ICMP_PHOTURIS_AUTH_FAILED },
	{ "decrypt-fail",	ICMP_PHOTURIS,	ICMP_PHOTURIS_DECRYPT_FAILED }
};

struct icmpcodeent icmp6_code[] = {
	{ "admin-unr", ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADMIN },
	{ "noroute-unr", ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE },
	{ "notnbr-unr",	ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOTNEIGHBOR },
	{ "beyond-unr", ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_BEYONDSCOPE },
	{ "addr-unr", ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADDR },
	{ "port-unr", ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOPORT },
	{ "transit", ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT },
	{ "reassemb", ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_REASSEMBLY },
	{ "badhead", ICMP6_PARAM_PROB, ICMP6_PARAMPROB_HEADER },
	{ "nxthdr", ICMP6_PARAM_PROB, ICMP6_PARAMPROB_NEXTHEADER },
	{ "redironlink", ND_REDIRECT, ND_REDIRECT_ONLINK },
	{ "redirrouter", ND_REDIRECT, ND_REDIRECT_ROUTER }
};
	

struct icmptypeent *
geticmptypebynumber(u_int8_t type, u_int8_t af)
{
	unsigned i;

	if (af != AF_INET6) {
		for(i=0; i < (sizeof (icmp_type) / sizeof(icmp_type[0])); i++) {
			if(type == icmp_type[i].type)
				return (&icmp_type[i]);
		}
	} else {
		for(i=0; i < (sizeof (icmp6_type) /
		    sizeof(icmp6_type[0])); i++) {
			if(type == icmp6_type[i].type)
				 return (&icmp6_type[i]);
		}
	}
	return (NULL);
}

struct icmptypeent *
geticmptypebyname(char *w, u_int8_t af)
{
	unsigned i;

	if (af != AF_INET6) {
		for(i=0; i < (sizeof (icmp_type) / sizeof(icmp_type[0])); i++) {
			if(!strcmp(w, icmp_type[i].name))
				return (&icmp_type[i]);
		}
	} else {
		for(i=0; i < (sizeof (icmp6_type) /
		    sizeof(icmp6_type[0])); i++) {
			if(!strcmp(w, icmp6_type[i].name))
				return (&icmp6_type[i]);
		}
	}
	return (NULL);
}

struct icmpcodeent *
geticmpcodebynumber(u_int8_t type, u_int8_t code, u_int8_t af)
{
	unsigned i;

	if (af != AF_INET6) {
		for(i=0; i < (sizeof (icmp_code) / sizeof(icmp_code[0])); i++) {
			if (type == icmp_code[i].type &&
			    code == icmp_code[i].code)
				return (&icmp_code[i]);
		}
	} else {
		for(i=0; i < (sizeof (icmp6_code) /
		   sizeof(icmp6_code[0])); i++) {
			if (type == icmp6_code[i].type &&
			    code == icmp6_code[i].code)
				return (&icmp6_code[i]);
		}
	}
	return (NULL);
}

struct icmpcodeent *
geticmpcodebyname(u_long type, char *w, u_int8_t af)
{
	unsigned i;

	if (af != AF_INET6) {
		for(i=0; i < (sizeof (icmp_code) / sizeof(icmp_code[0])); i++) {
			if (type == icmp_code[i].type &&
			    !strcmp(w, icmp_code[i].name))
				return (&icmp_code[i]);
		}
	} else {
		for(i=0; i < (sizeof (icmp6_code) /
		    sizeof(icmp6_code[0])); i++) {
			if (type == icmp6_code[i].type &&
			    !strcmp(w, icmp6_code[i].name))
				return (&icmp6_code[i]);
		}
	}
	return (NULL);
}

int
unmask(struct pf_addr *m, u_int8_t af)
{
	int i = 31, j = 0, b = 0, msize;
	u_int32_t tmp;

	if (af == AF_INET)
		msize = 1;
	else
		msize = 4;
	while (j < msize && m->addr32[j] == 0xffffffff) {
			b += 32;	
			j++;
	}
	if (j < msize) {
		tmp = ntohl(m->addr32[j]);
		for (i = 31; tmp & (1 << i); --i)
			b++;
	}
	return (b);
}

void
print_addr(struct pf_addr *addr, struct pf_addr *mask, u_int8_t af)
{
	char buf[48];
	const char *bf;

	bf = inet_ntop(af, addr, buf, sizeof(buf));
	printf("%s", bf);
	if (mask != NULL) {
		if (!PF_AZERO(mask, af))
			printf("/%u", unmask(mask, af));
	} 
}

void
print_host(struct pf_state_host *h, u_int8_t af)
{
	u_int16_t p = ntohs(h->port);

	print_addr(&h->addr, NULL, af);
	if (p) {
		if (af == AF_INET)
			printf(":%u", p);
		else
			printf("[%u]", p);
	}
}
		

void
print_seq(struct pf_state_peer *p)
{
	if (p->seqdiff)
		printf("[%u + %u](+%u)", p->seqlo, p->seqhi - p->seqlo,
		    p->seqdiff);
	else
		printf("[%u + %u]", p->seqlo, p->seqhi - p->seqlo);
}

void
print_port(u_int8_t op, u_int16_t p1, u_int16_t p2, char *proto)
{
	struct servent *s = getservbyport(p1, proto);

	p1 = ntohs(p1);
	p2 = ntohs(p2);
	printf("port ");
	if (op == PF_OP_IRG)
		printf("%u >< %u ", p1, p2);
	else if (op == PF_OP_XRG)
		printf("%u <> %u ", p1, p2);
	else if (op == PF_OP_EQ) {
		if (s != NULL)
			printf("= %s ", s->s_name);
		else
			printf("= %u ", p1);
	} else if (op == PF_OP_NE) {
		if (s != NULL)
			printf("!= %s ", s->s_name);
		else
			printf("!= %u ", p1);
	} else if (op == PF_OP_LT)
		printf("< %u ", p1);
	else if (op == PF_OP_LE)
		printf("<= %u ", p1);
	else if (op == PF_OP_GT)
		printf("> %u ", p1);
	else if (op == PF_OP_GE)
		printf(">= %u ", p1);
}

void
print_flags(u_int8_t f)
{
	int i;

	for (i = 0; i < 6; ++i)
		if (f & (1 << i))
			printf("%c", tcpflags[i]);
}

void
print_nat(struct pf_nat *n)
{
	if (n->no)
		printf("no ");
	printf("nat ");
	if (n->ifname[0]) {
		printf("on ");
		if (n->ifnot)
			printf("! ");
		printf("%s ", n->ifname);
	}
	if (n->proto) {
		struct protoent *p = getprotobynumber(n->proto);
		if (p != NULL)
			printf("proto %s ", p->p_name);
		else
			printf("proto %u ", n->proto);
	}
	printf("from ");
	if (!PF_AZERO(&n->saddr, n->af) || !PF_AZERO(&n->smask, n->af)) {
		if (n->snot)
			printf("! ");
		print_addr(&n->saddr, &n->smask, n->af);
		printf(" ");
	} else
		printf("any ");
	printf("to ");
	if (!PF_AZERO(&n->daddr, n->af) || !PF_AZERO(&n->dmask, n->af)) {
		if (n->dnot)
			printf("! ");
		print_addr(&n->daddr, &n->dmask, n->af);
		printf(" ");
	} else
		printf("any ");
	if (!n->no) {
		printf("-> ");
		print_addr(&n->raddr, NULL, n->af);
	}
	printf("\n");
}

void
print_binat(struct pf_binat *b)
{
	if (b->no)
		printf("no ");
	printf("binat ");
	if (b->ifname[0]) {
		printf("on ");
		printf("%s ", b->ifname);
	}
	if (b->proto) {
		struct protoent *p = getprotobynumber(b->proto);
		if (p != NULL)
			printf("proto %s ", p->p_name);
		else
			printf("proto %u ", b->proto);
	}
	printf("from ");
	print_addr(&b->saddr, NULL, b->af);
	printf(" ");
	printf("to ");
	if (!PF_AZERO(&b->daddr, b->af) || !PF_AZERO(&b->dmask, b->af)) {
		if (b->dnot)
			printf("! ");
		print_addr(&b->daddr, &b->dmask, b->af);
		printf(" ");
	} else
		printf("any ");
	if (!b->no) {
	 	printf("-> ");
		print_addr(&b->raddr, NULL, b->af);
	}
	printf("\n");
}

void
print_rdr(struct pf_rdr *r)
{
	if (r->no)
		printf("no ");
	printf("rdr ");
	if (r->ifname[0]) {
		printf("on ");
		if (r->ifnot)
			printf("! ");
		printf("%s ", r->ifname);
	}
	if (r->proto) {
		struct protoent *p = getprotobynumber(r->proto);
		if (p != NULL)
			printf("proto %s ", p->p_name);
		else
			printf("proto %u ", r->proto);
	}
	printf("from ");
	if (!PF_AZERO(&r->saddr, r->af) || !PF_AZERO(&r->smask, r->af)) {
		if (r->snot)
			printf("! ");
		print_addr(&r->saddr, &r->smask, r->af);
		printf(" ");
	} else
		printf("any ");
	printf("to ");
	if (!PF_AZERO(&r->daddr, r->af) || !PF_AZERO(&r->dmask, r->af)) {
		if (r->dnot)
			printf("! ");
		print_addr(&r->daddr, &r->dmask, r->af);
		printf(" ");
	} else
		printf("any ");
	if (r->dport) {
		printf("port %u", ntohs(r->dport));
		if (r->opts & PF_DPORT_RANGE)
			printf(":%u", ntohs(r->dport2));
	}
	if (!r->no) {
		printf(" -> ");
		print_addr(&r->raddr, NULL, r->af);
		printf(" ");
		if (r->rport) {
			printf("port %u", ntohs(r->rport));
			if (r->opts & PF_RPORT_RANGE)
				printf(":*");
		}
	}
	printf("\n");
}

char *pf_reasons[PFRES_MAX+1] = PFRES_NAMES;
char *pf_fcounters[FCNT_MAX+1] = FCNT_NAMES;

void
print_status(struct pf_status *s)
{

	time_t t = time(NULL);
	int i;

	printf("Status: %s  Time: %u  Since: %u  Debug: ",
	    s->running ? "Enabled" : "Disabled",
	    t, s->since);
	switch (s->debug) {
		case 0:
			printf("None");
			break;
		case 1:
			printf("Urgent");
			break;
		case 2:
			printf("Misc");
			break;
	}
	printf("\nBytes In IPv4: %-10llu  Bytes Out: %-10llu\n",
	    s->bcounters[0][PF_IN], s->bcounters[0][PF_OUT]);
	printf("         IPv6: %-10llu  Bytes Out: %-10llu\n",
	    s->bcounters[1][PF_IN], s->bcounters[1][PF_OUT]);
	printf("Inbound Packets IPv4:  Passed: %-10llu  Dropped: %-10llu\n",
	    s->pcounters[0][PF_IN][PF_PASS],
	    s->pcounters[0][PF_IN][PF_DROP]);
	printf("                IPv6:  Passed: %-10llu  Dropped: %-10llu\n",
	    s->pcounters[1][PF_IN][PF_PASS],
	    s->pcounters[1][PF_IN][PF_DROP]);
	printf("Outbound Packets IPv4: Passed: %-10llu  Dropped: %-10llu\n",
	    s->pcounters[0][PF_OUT][PF_PASS],
	    s->pcounters[0][PF_OUT][PF_DROP]);
	printf("                 IPv6: Passed: %-10llu  Dropped: %-10llu\n",
	    s->pcounters[1][PF_OUT][PF_PASS],
	    s->pcounters[1][PF_OUT][PF_DROP]);
	printf("States: %u\n", s->states);
	printf("pf Counters\n");
	for (i = 0; i < FCNT_MAX; i++)
		printf("%-25s %-8lld\n", pf_fcounters[i],
		    s->fcounters[i]);
	printf("Counters\n");
	for (i = 0; i < PFRES_MAX; i++)
		printf("%-25s %-8lld\n", pf_reasons[i],
		    s->counters[i]);
}

void
print_state(struct pf_state *s, int opts)
{
	struct pf_state_peer *src, *dst;
	struct protoent *p;
	u_int8_t hrs, min, sec;

	if (s->direction == PF_OUT) {
		src = &s->src;
		dst = &s->dst;
	} else {
		src = &s->dst;
		dst = &s->src;
	}
	if ((p = getprotobynumber(s->proto)) != NULL)
		printf("%s ", p->p_name);
	else
		printf("%u ", s->proto);
	if (PF_ANEQ(&s->lan.addr, &s->gwy.addr, s->af) ||
	    (s->lan.port != s->gwy.port)) {
		print_host(&s->lan, s->af);
		if (s->direction == PF_OUT)
			printf(" -> ");
		else
			printf(" <- ");
	}
	print_host(&s->gwy, s->af);
	if (s->direction == PF_OUT)
		printf(" -> ");
	else
		printf(" <- ");
	print_host(&s->ext, s->af);

	printf("    ");
	if (s->proto == IPPROTO_TCP) {
		if (src->state <= TCPS_TIME_WAIT &&
		    dst->state <= TCPS_TIME_WAIT) {
			printf("   %s:%s\n", tcpstates[src->state],
			    tcpstates[dst->state]);
		} else {
			printf("   <BAD STATE LEVELS>\n");
		}
		if (opts & PF_OPT_VERBOSE) {
			printf("   ");
			print_seq(src);
			printf("  ");
			print_seq(dst);
			printf("\n");
		}
	} else {
		printf("   %u:%u\n", src->state, dst->state);
	}

	if (opts & PF_OPT_VERBOSE) {
		sec = s->creation % 60;
		s->creation /= 60;
		min = s->creation % 60;
		s->creation /= 60;
		hrs = s->creation;
		printf("   age %.2u:%.2u:%.2u", hrs, min, sec);
		sec = s->expire % 60;
		s->expire /= 60;
		min = s->expire % 60;
		s->expire /= 60;
		hrs = s->expire;
		printf(", expires in %.2u:%.2u:%.2u", hrs, min, sec);
		printf(", %u pkts, %u bytes\n", s->packets, s->bytes);
	}
}

void
print_rule(struct pf_rule *r)
{
	printf("@%d ", r->nr);
	if (r->action == PF_PASS)
		printf("pass ");
	else if (r->action == PF_DROP) {
		printf("block ");
		if (r->rule_flag & PFRULE_RETURNRST)
			printf("return-rst ");
		else if (r->return_icmp) {
			struct icmpcodeent *ic;

			if (r->af != AF_INET6)
				printf("return-icmp");
			else
				printf("return-icmp6");
			ic = geticmpcodebynumber(r->return_icmp >> 8,
			    r->return_icmp & 255, r->af);

			if (ic == NULL)
				printf("(%u) ", r->return_icmp & 255);
			else if ((r->af != AF_INET6 && ic->code != ICMP_UNREACH_PORT) ||
			    (r->af == AF_INET6 && ic->code != ICMP6_DST_UNREACH_NOPORT))
				printf("(%s) ", ic->name);
			else
				printf(" ");
		}
	} else
		printf("scrub ");
	if (r->direction == 0)
		printf("in ");
	else
		printf("out ");
	if (r->log == 1)
		printf("log ");
	else if (r->log == 2)
		printf("log-all ");
	if (r->quick)
		printf("quick ");
	if (r->ifname[0])
		printf("on %s ", r->ifname);
	if (r->rt) {
		if (r->rt == PF_ROUTETO)
			printf("route-to ");
		else if (r->rt == PF_DUPTO)
			printf("dup-to ");
		else if (r->rt == PF_FASTROUTE)
			printf("fastroute");
		if (r->rt_ifname[0])
			printf("%s", r->rt_ifname);
		if (r->af && !PF_AZERO(&r->rt_addr, r->af)) {
			printf(":");
			print_addr(&r->rt_addr, NULL, r->af);
		}
		printf(" ");
	}
	if (r->af) {
		if (r->af == AF_INET) 
			printf("inet ");
		else
			printf("inet6 ");
	}
	if (r->proto) {
		struct protoent *p = getprotobynumber(r->proto);
		if (p != NULL)
			printf("proto %s ", p->p_name);
		else
			printf("proto %u ", r->proto);
	}
	if (PF_AZERO(&r->src.addr, AF_INET6) &&
	    PF_AZERO(&r->src.mask, AF_INET6) &&
	    !r->src.port_op && PF_AZERO(&r->dst.addr, AF_INET6) &&
	    PF_AZERO(&r->dst.mask, AF_INET6) && !r->dst.port_op)
		printf("all ");
	else {
		printf("from ");
		if (PF_AZERO(&r->src.addr, AF_INET6) &&
		    PF_AZERO(&r->src.mask, AF_INET6))
			printf("any ");
		else {
			if (r->src.not)
				printf("! ");
			print_addr(&r->src.addr, &r->src.mask, r->af);
			printf(" ");
		}
		if (r->src.port_op)
			print_port(r->src.port_op, r->src.port[0],
			    r->src.port[1],
			    r->proto == IPPROTO_TCP ? "tcp" : "udp");

		printf("to ");
		if (PF_AZERO(&r->dst.addr, AF_INET6) &&
		    PF_AZERO(&r->dst.mask, AF_INET6))
			printf("any ");
		else {
			if (r->dst.not)
				printf("! ");
			print_addr(&r->dst.addr, &r->dst.mask, r->af);
			printf(" ");
		}
		if (r->dst.port_op)
			print_port(r->dst.port_op, r->dst.port[0],
			    r->dst.port[1],
			    r->proto == IPPROTO_TCP ? "tcp" : "udp");
	}
	if (r->flags || r->flagset) {
		printf("flags ");
		print_flags(r->flags);
		printf("/");
		print_flags(r->flagset);
		printf(" ");
	}
	if (r->type) {
		struct icmptypeent *p;

		p = geticmptypebynumber(r->type-1, r->af);
		if (r->af != AF_INET6)
			printf("icmp-type");
		else
			printf("ipv6-icmp-type");
		if (p != NULL)
			printf(" %s ", p->name);
		else
			printf(" %u ", r->type-1);
		if (r->code) {
			struct icmpcodeent *p;

			p = geticmpcodebynumber(r->type-1, r->code-1, r->af);
			if (p != NULL)
				printf("code %s ", p->name);
			else
				printf("code %u ", r->code-1);
		}
	}
	if (r->keep_state == PF_STATE_NORMAL)
		printf("keep state ");
	else if (r->keep_state == PF_STATE_MODULATE)
		printf("modulate state ");
	if (r->rule_flag & PFRULE_NODF)
		printf("no-df ");
	if (r->min_ttl)
		printf("min-ttl %d ", r->min_ttl);
	if (r->allow_opts)
		printf("allow-opts ");
	if (r->label[0])
		printf("label %s", r->label);

	printf("\n");
}

int
parse_flags(char *s)
{
	char *p, *q;
	u_int8_t f = 0;

	for (p = s; *p; p++) {
		if ((q = strchr(tcpflags, *p)) == NULL)
			return -1;
		else
			f |= 1 << (q - tcpflags);
	}
	return (f ? f : 63);
}
