#include <stdarg.h>
#include <stdio.h>

/*
    변수 설명
*/

/* token, token constant, token level(precedence), current char */
int tok, tok_constant, tok_level, ch; 

/* variables table for accessing var's value within stack frame */
int var_table;

/* local variable offset within var_table */
int var_local_offset;
int var_global_offset;

/* return address list (when backpatching) */
int ra_list;

/* machine code */
int code_start_ptr, code_current_ptr;

/* file pointer */
int file_ptr;

/* symbol stack */
int sym_stack_start_ptr;
int sym_stack_current_ptr;

/* processing macro */
int macro_ptr;
int ch_before_macro;

/* identifier */
int identifier_last;

/* segments / offset related with ELF file format*/
int data, text, data_offset;

/* 
allocate 99999Byte in Heap, using calloc 
--> sym_stack string
--> machine code buffer
--> variable table
*/
#define ALLOC_SIZE 99999

/* allow to emit ELF file */
// #define ELFOUT

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

#define LOCAL               0x200

#define SYM_FORWARD         0
#define SYM_DEFINE          1

/* tokens in string heap */
#define TAG_TOK             ' '
#define TAG_MACRO           2

add_ch_to_sym_stack(ch)
{
    /* add char(1Byte) to sym_stack */
    *(char *)sym_stack_current_ptr++ = ch;
}

/*
    read char..

    from memory: if we encounter MACRO(#define)
    from FILE: otherwise 
*/
read_ch()
{
    if (macro_ptr) {
        ch = *(char *)macro_ptr++;
        if (ch == TAG_MACRO) {
            macro_ptr = 0;
            ch = ch_before_macro;
        }
    } else
        ch = fgetc(file_ptr);
}

is_identifier()
{
    return isalnum(ch) | ch == '_';
}

process_escape()
{
    if (ch == '\\') {
        read_ch();
        if (ch == 'n')
            ch = '\n';
    }
}

read_token()
{
    int op_str, left, ahead; 

    /* space, #define process */
    while (isspace(ch) | ch == '#') {
        if (ch == '#') {
            read_ch();
            read_token();
            if (tok == TOK_DEFINE) {
                read_token();
                add_ch_to_sym_stack(TAG_TOK);
                *(int *)tok = SYM_DEFINE;
                *(int *)(tok + 4) = sym_stack_current_ptr;
            }
            /* right before newline, add ch to sym_stack*/
            while (ch != '\n') {
                add_ch_to_sym_stack(ch);
                read_ch();
            }
            add_ch_to_sym_stack(ch);
            add_ch_to_sym_stack(TAG_MACRO);
        }
        /* if we get space, read more and more */
        read_ch();
    }

    /* initialise token with ch, token level with 0 */
    tok_level = 0;
    tok = ch;

    /* encode identifier & numbers */
    if (is_identifier()) {
        add_ch_to_sym_stack(TAG_TOK);
        while (is_identifier()) {
            add_ch_to_sym_stack(ch);
            read_ch();
        }
        if (isdigit(tok)) {
            /* token constant <-- number constant */
            tok_constant = strtol(identifier_last, 0, 0);
            tok = TOK_NUM;
        } else {
            /* process identifier */
            *(char *)sym_stack_current_ptr = TAG_TOK;
            /* get position offset of identifier in sym_stack */
            tok = strstr(sym_stack_start_ptr, identifier_last - 1) - sym_stack_start_ptr;
            /* mark end of identifier for dlsym() */
            *(char *)sym_stack_current_ptr = 0;
            /* token type e.g. TOK_INT, TOK_WHLIE ... */
            tok = tok * 8 + TOK_IDENT;

            if (tok > TOK_DEFINE) {
                /* get MACRO name */
                tok = var_table + tok;
                if (*(int *)tok == SYM_DEFINE) {
                    macro_ptr = *(int *)(tok + 4);
                    ch_before_macro = ch;
                    read_ch();
                    read_token();
                }
            }
        }
    } else {
        read_ch();
        /* if we met opening single quote */
        if (tok == '\'') {
            /* change token type since we use int type (char constant('a') -> int) */
            tok = TOK_NUM; 
            process_escape();
            tok_constant = ch;
            read_ch(); /* read char constant */
            read_ch(); /* read closing single quote */
        } else if (tok == '/' & ch == '*') {
            /* process comment */
            read_ch();
            while (ch) {
                while (ch != '*')
                    read_ch();
                read_ch();
                /* end of comment */
                if (ch == '/') 
                    ch = 0;
            }
            read_ch();
            read_token();
        } else {
            op_str = "++#m--%am*@R<^1c/@%[_[H3c%@%[_[H3c+@.B#d-@%:_^BKd<<Z/03e>>`/03e<=0f>=/f<@.f>@1f==&g!=\'g&&k||#l&@.BCh^@.BSi|@.B+j~@/%Yd!@&d*@b";
            /* left = '+' from "++" */
            while (left = *(char *)op_str++) {
                ahead = *(char *)op_str++;
                tok_constant = 0;
                while ((tok_level = *(char *)op_str++ - 'b') < 0) {
                    tok_constant = tok_constant * 64 + tok_level + 64;
                }

                if (left == tok & (ahead == ch | ahead == '@')) {
                    if (ahead == ch) {
                        read_ch();
                        /* dummy token for double tokens */
                        tok = TOK_DUMMY;
                    }
                    break;
                }
            }
        }
    }
}

/* function to print error messages via STDERR */
/* can print with variable arguments */
void error(char *fmt, ...)
{
   va_list arg_ptr;

    va_start(arg_ptr, fmt);
    fprintf(stderr, "%d: ", ftell((FILE *)file_ptr));
    vfprintf(stderr, fmt, arg_ptr);
    fprintf(stderr, "\n");
    exit(1);
    va_end(arg_ptr);
}

void skip(ch) 
{
    if (tok != ch) {
        error("'%c' expected", ch);
    }
    
    read_token();
}
