/* allocation size of each segments, data structure */
#define ALLOC_SIZE      99999

/* ELF information used in Dynamic linking */
#define DT_NEEDED       1
#define DT_HASH         4
#define DT_SYMTAB       6
#define DT_STRTAB       5
#define DT_STRSZ        10
#define DT_SYMENT       11
#define DT_REL          17
#define DT_RELSZ        18
#define DT_RELENT       19
#define DT_NULL         0

/* additional ELF output defines */


/* defines used in parsing */
#define TOK_STR_SIZE        48
#define TOK_IDENT           0x100
#define TOK_INT             0x100
#define TOK_IF              0x120
#define TOK_ELSE            0x138
#define TOK_WHILE           0x160
#define TOK_BREAK           0x190  
#define TOK_RETURN          0x1c0
#define TOK_FOR             0x1f8
#define TOK_DEFINE          0x218
#define TOK_MAIN            0x250

#define TOK_DUMMY           1
#define TOK_NUM             2

