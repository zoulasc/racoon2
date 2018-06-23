#ifndef _SCRIPT_H_
#define _SCRIPT_H_

/* Script hooks */
#define SCRIPT_PHASE1_UP	0
#define SCRIPT_PHASE1_DOWN	1
#define	SCRIPT_PHASE2_UP	2
#define	SCRIPT_PHASE2_DOWN	3
#define	SCRIPT_PHASE1_REKEY	4
#define	SCRIPT_PHASE2_REKEY	5
#define	SCRIPT_MIGRATE		6
#define SCRIPT_MAX		6
#define	SCRIPT_NUM		(SCRIPT_MAX + 1)

extern char *script_names[SCRIPT_NUM];

extern int script_env_append(char ***, int *, const char *, const char *);
extern void script_env_free(char **);
extern int script_exec(const char *, int, char *const*);


#endif
