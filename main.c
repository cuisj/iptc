#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libiptc/libiptc.h>

static void add_rule_match()
{
	struct iptc_handle *h = NULL;
	struct ipt_entry *e = NULL;
	struct ipt_entry_match *pm = NULL;
	struct ipt_tcp *ptcp = NULL;
	struct ipt_entry_target *pt = NULL;

	size_t match_size, target_size, size;

	match_size = XT_ALIGN(sizeof(*pm)) + XT_ALIGN(sizeof(*ptcp));
	target_size = XT_ALIGN(sizeof(*pt)) + XT_ALIGN(sizeof(int));
	size = sizeof(*e) + match_size + target_size;

	h = iptc_init("filter");
	if (!h) {
		printf("iptc_init: %s\n", iptc_strerror(errno));
		goto over;
	}

	// entry
	e = calloc(1, size);
	e->ip.src.s_addr = inet_addr("192.168.3.2");
	e->ip.smsk.s_addr = -1;
	e->ip.proto = 6; // tcp
	e->target_offset = sizeof(*e) + match_size;
	e->next_offset = size;

	// match
	pm = (struct ipt_entry_match *)e->elems;
	pm->u.user.match_size = match_size;
	strcpy(pm->u.user.name, "tcp");

	ptcp = (struct ipt_tcp *)pm->data;
	ptcp->spts[0] = 0;
	ptcp->spts[1] = 0xFFFF;
	ptcp->dpts[0] = 80;
	ptcp->dpts[1] = 80;

	// target
	pt = (struct ipt_entry_target *)(e->elems + match_size);
	pt->u.user.target_size = target_size;
	strcpy(pt->u.user.name, "ACCEPT");

	if (!iptc_append_entry("INPUT", e, h)) {
		printf("iptc_append_entry: %s\n", iptc_strerror(errno));
		goto over;
	}

	if (!iptc_commit(h)) {
		printf("iptc_commit: %s\n", iptc_strerror(errno));
		goto over;
	}

over:
	if (h)
		iptc_free(h);

	if (e)
		free(e);

	return;
}

static void add_rule()
{
	struct iptc_handle *h = NULL;
	struct ipt_entry *e = NULL;
	struct ipt_entry_target *pt = NULL;
	size_t target_size;

	h = iptc_init("filter");
	if (!h) {
		printf("iptc_init: %s\n", iptc_strerror(errno));
		goto over;
	}

	target_size = XT_ALIGN(sizeof(*pt)) + XT_ALIGN(sizeof(int));

	e = calloc(1, sizeof(*e) + target_size);
	strcpy(e->ip.iniface, "eth0");
	memset(e->ip.iniface_mask, 0xFF, strlen("eth0") + 1);

	e->ip.proto = 1;
	e->target_offset = sizeof(*e);
	e->next_offset = sizeof(*e) + target_size;

	pt = (struct ipt_entry_target *)e->elems;
	pt->u.user.target_size = target_size;
	strcpy(pt->u.user.name, "DROP");

	if (!iptc_append_entry("INPUT", e, h)) {
		printf("iptc_append_entry: %s\n", iptc_strerror(errno));
		goto over;
	}

	if (!iptc_commit(h)) {
		printf("iptc_commit: %s\n", iptc_strerror(errno));
		goto over;
	}

over:
	if (h)
		iptc_free(h);

	if (e)
		free(e);

	return;
}

static void flush_entries()
{
	struct iptc_handle *h = NULL;

	h = iptc_init("filter");
	if (!h) {
		printf("iptc_init: %s\n", iptc_strerror(errno));
		goto over;
	}

	if (!iptc_flush_entries("INPUT", h)) {
		printf("iptc_flush_entries: %s\n", iptc_strerror(errno));
		goto over;
	}

	if (!iptc_commit(h)) {
		printf("iptc_commit: %s\n", iptc_strerror(errno));
		goto over;
	}

over:
	if (h)
		iptc_free(h);
}

static void del_rule_match()
{
	struct iptc_handle *h = NULL;
	struct ipt_entry *e = NULL;
	struct ipt_entry_match *pm = NULL;
	struct ipt_tcp *ptcp = NULL;
	struct ipt_entry_target *pt = NULL;

	size_t match_size, target_size, size;

	match_size = XT_ALIGN(sizeof(*pm)) + XT_ALIGN(sizeof(*ptcp));
	target_size = XT_ALIGN(sizeof(*pt)) + XT_ALIGN(sizeof(int));
	size = sizeof(*e) + match_size + target_size;

	h = iptc_init("filter");
	if (!h) {
		printf("iptc_init: %s\n", iptc_strerror(errno));
		goto over;
	}

	// entry
	e = calloc(1, size);
	e->ip.src.s_addr = inet_addr("192.168.3.2");
	e->ip.smsk.s_addr = -1;
	e->ip.proto = 6; // tcp
	e->target_offset = sizeof(*e) + match_size;
	e->next_offset = size;

	// match
	pm = (struct ipt_entry_match *)e->elems;
	pm->u.user.match_size = match_size;
	strcpy(pm->u.user.name, "tcp");

	ptcp = (struct ipt_tcp *)pm->data;
	ptcp->spts[0] = 0;
	ptcp->spts[1] = 0xFFFF;
	ptcp->dpts[0] = 80;
	ptcp->dpts[1] = 80;

	// target
	pt = (struct ipt_entry_target *)(e->elems + match_size);
	pt->u.user.target_size = target_size;
	strcpy(pt->u.user.name, "ACCEPT");

	if (!iptc_delete_entry("INPUT", e, "", h)) {
		printf("iptc_append_entry: %s\n", iptc_strerror(errno));
		goto over;
	}

	if (!iptc_commit(h)) {
		printf("iptc_commit: %s\n", iptc_strerror(errno));
		goto over;
	}

over:
	if (h)
		iptc_free(h);

	if (e)
		free(e);

	return;
}

int main(void)
{
	flush_entries();
	add_rule();
	add_rule_match();
	del_rule_match();
}
