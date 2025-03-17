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

/* put machine code into machine code buffer */
generate_machine_code(bytes) 
{
    while (bytes && bytes != -1) {
        *(char *)code_current_ptr++ = bytes;
        /*  emit machine code(0 ~ 4 bytes) buffer
            into machine code buffer
            with little endian 
        */
        bytes = bytes >> 8;
    }
}


/* put a 32 bit little endian word 'n' at unaligned address 't' */
/* 'generally' used to put word into memory address */
add_word_to_addr(addr, word) {
    *(char *)addr++ = word;
    *(char *)addr++ = word >> 8;
    *(char *)addr++ = word >> 16;
    *(char *)addr++ = word >> 24;
}
/* read 32bit word from memory address */
read_word_from_addr(addr)
{
    int word;
    /* first 1 byte (LSB)*/
    int a0 = *(char *)addr & 0xff;
    int a1 = *(char *)(addr + 1) & 0xff << 8;
    int a2 = *(char *)(addr + 2) & 0xff << 16;
    int a3 = *(char *)(addr + 3) & 0xff << 24;

    return a3 | a2 | a1 | a0;
}

/*  
    patch symbol reference 
    because our compiler has 1 pass
    We should resolve forward reference by back patching

    when we met 'return' statement, 
    we should read all of that function
    to know where the function ends.
    so we can patch that unresolved symbol
*/
patch_symbol_ref(addr, sym_position) 
{
    int n;
    /* pointer of unresolved symbols list(address chain) */
    /* we should resolve it iteratively */
    while (addr) {
        /* iterate unresolved symbols */
        n = read_word_from_addr(addr);
        /* mov / lea instruction with **absolute** reference*/
        if (*(char *)(addr - 1) == 0x05) {
           if (sym_position >= data && sym_position < var_global_offset) 
                 /* if symbol exists in data segment */
                add_word_to_addr(addr, sym_position + data_offset);
            else
                /* if symbol exists in code segment */
                add_word_to_addr(addr, sym_position - code_start_ptr + text + data_offset);
        /* relative reference */
        } else {
            add_word_to_addr(addr, sym_position - addr - 4);
        }
        addr = n;
    }
}

generate_machine_code_with_addr(word, addr) 
{
    generate_machine_code(word);
    /* append address to machine code */
    add_word_to_addr(code_current_ptr, addr);
    /* address we appended right before */
    addr = code_current_ptr;
    code_current_ptr = code_current_ptr + 4;

    /* return address we appended */
    return addr;
}

/* helper: load imm value to register eax */
load_immediate(imm)
{
    /* mov $xx, %eax */
    generate_machine_code_with_addr(0xb8, imm);
}

/* unconditional jump */
generate_jump(addr)
{
    return generate_machine_code_with_addr(0xe9, addr);   
}

generate_cond_jump(not_equal, addr) 
{
    /* 
        0xfc085
        : generate 'test %eax, %eax' which instruction operate
        AND on %eax register.
        After that operation, set the flags whether %eax is 0 or not
    */
    generate_machine_code(0x0fc085); 
    /*  
        l = 0 ==> 0x84 = je, jump if %eax is 0 
        l = 1 ==> 0x85 = jne, jump if %eax is not 0 
     */
    return generate_machine_code_with_addr(0x84 + not_equal, addr);
}

generate_compare(cond)
{
    /* 
        cmp %eax, %ecx 
        depending on result ==> set CPU flag 
    */
    generate_machine_code(0xc139);
    /* mov $0, %eax */
    load_immediate(0);
    generate_machine_code(0x0f);
    /*
        set eax to 1 if equal, not equal, less, ...
        sete, setne, setle, setg 
        which of them ?
        ... depends on (0x90 + cond)
    */
    generate_machine_code(cond + 0x90);
    
    /* 
        this byte(0xc0) determines 
        which bytes setxx should modify
        0xc0 ==> LSByte
    */
    generate_machine_code(0xc0);
}

 /*
        depending on l, generate different MOV instruction
        l = 6: mov %eax, EA
        l = 8: mov EA, %eax
        l = 10: lea EA, %eax
    */
generate_move(l, addr)
{
   
    int n;
    generate_machine_code(l + 0x83);
    /* n is value of address */
    n = *(int *)addr;
    /* < LOCAL means we will move local variable(in stack frame) */
    if (n && n < LOCAL) {
        generate_machine_code_with_addr(0x85, n);
    } else {
        /* process global or symbol */
        addr = addr + 4;
        *(int *)addr = generate_machine_code_with_addr(0x05, *(int *)addr);
    }
}

/* l is 1 if '=' parsing wanted (quick hack)*/

parse_unary_expr(l) {
    int expr_type, tmp_tok, tmp_tok_constant, tmp_tok_level;

    /* type of expression 0 = forward, 1 = value, other = lvalue */
    expr_type = 1; /* default value = 1 ==> expression as value */

    /* parse string literal */
    if (tok == '\"') {
        /* load string literal's **address** to %eax */
        load_immediate(var_global_offset + data_offset);
        while (ch != '\"') {
            process_escape();
            *(char *)var_global_offset++ = ch;
            read_ch();
        }
        /* insert terminating symbol to end of string*/
        *(char *)var_global_offset = 0;

        /* 
            align 4 bytes boundary 
            -4 = 11111....11100 (2's complement)
            1. if glo = 5 --> ....00101
            2. glo + 4 = 9 --> ...01001
            3. & -4 = ...1000 = 8 
            --> 5바이트까지 차지했네..  다음엔 8에서 시작한다
        */
        var_global_offset = var_global_offset + 4 & -4;
        read_ch();
        read_token();
    } else {
        /* before read_token(), we should save our token's info in tmp variables */
        tmp_tok_level = tok_level;
        tmp_tok_constant = tok_constant;
        tmp_tok = tok;

        read_token(); /* tok updated */

        if (tmp_tok == TOK_NUM) {
            load_immediate(tmp_tok_constant);
        } else if (tmp_tok_level == 2) {
            /* -, +, !, ~ */
            parse_unary_expr(0);
            /* mov $0, %ecx */
            generate_machine_code_with_addr(0xb9, 0);
            if (tmp_tok == '!')
                generate_compare(tmp_tok_constant);
            else
                generate_machine_code(tmp_tok_constant);
        } else if (tmp_tok == '(') {
            parse_expr();
            skip(')');
        } else if (tmp_tok == '*') {
            /* hard to understand */
            /* parse cast */
            skip('*');
            tmp_tok = tok; /* get type */
            read_token(); /* skip int/char/void */
            read_token(); /* skip '*' or ')' */

            if (tok == '*') {
                /* function pointer */
                skip('*');
                skip(')');
                skip('(');
                skip(')');
                tmp_tok = 0;
            }
            skip(')');
            parse_unary_expr(0);
            if (tok == '=') {
                read_token();
                /* %eax has pointer address */
                generate_machine_code(0x50); /* push %eax */
                parse_expr();
                generate_machine_code(0x59); /* pop %ecx */
                /* movl %eax/%al, (%ecx) */
                generate_machine_code(0x0188 + (tmp_tok == TOK_INT)); 
            } else if (tmp_tok) {
                if (tmp_tok == TOK_INT)
                    /* store 4byte*/
                    generate_machine_code(0x8b);
                else
                    generate_machine_code(0xbe0f); /* movsbl (%eax), %(eax) */
                code_current_ptr++; /* add zero in code */
            }
        } else if (tmp_tok == '&') {
            generate_move(10, tok); /* leal EA, %eax */
            read_token();
        } else {
            expr_type = 0;
            if (tok == '=' & l) {
                /* assignment */
                read_token();
                parse_expr();
                generate_move(6, tmp_tok); /* mov %eax, EA */
            } else if (tok != '(') {
                /* variable */
                generate_move(8, tmp_tok); /* mov EA, %eax */
                if (tok_level == 11) {
                    generate_move(0, tmp_tok);
                    generate_machine_code(tok_constant);
                    read_token();
                }
            }
        }
    }
    /* function call */
    if (tok == '(') {
        if (expr_type) 
            generate_machine_code(0x50); /* push %eax */
        
        /* push args and invert order */
        tmp_tok_constant = generate_machine_code_with_addr(0xec81, 0); /* sub $xxx, %esp */
        read_token();
        l = 0;
        while (tok != ')') {
            /* process arguments */
            parse_expr();
            generate_machine_code_with_addr(0x248489, l); /* movl %eax, xxx(%esp) */
            if (tok == ',')
                read_token();
            l = l + 4;
        }

        add_word_to_addr(tmp_tok_constant, l);
        read_token();
        if (expr_type) {
            /* indirect call using function pointer */
            generate_machine_code_with_addr(0x2494ff, l); /* call *xxx(%esp) */
            l = l + 4;
        } else {
            /* direct call */
            /* forward reference */
            tmp_tok = tmp_tok + 4;
            *(int *)tmp_tok = generate_machine_code_with_addr(0xe8, *(int *)tmp_tok);
        }

        if (expr_type) 
            generate_machine_code_with_addr(0xc481, l); /* add $xxx, %esp */
    }

}