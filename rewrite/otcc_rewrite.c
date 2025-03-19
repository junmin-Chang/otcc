#include <stdarg.h>
#include <stdio.h>

/* token, token constant(value), token level(precedence), current char */
int tok, tok_constant, tok_level, ch; 

/* variables table for accessing var's value within stack frame */
int var_table;

/* local variable offset within var_table */
int var_local_offset;

/* pointer for global variable in data segment */
int data_segment_current;

/* return address list (when backpatching) */
int ra_list;

/* pointers for machine code in text segment*/
int text_segment_start, text_segment_current;

/* file pointer */
int file_ptr;

/* pointers for symbol stack */
int sym_stack_start_ptr;
int sym_stack_current_ptr;

/* processing macro */
int macro_ptr;
int ch_before_macro;

/* identifier */
int identifier_last;

/* segments / offset related with ELF file format*/
int data_segment_start, text, data_offset;

/* (global) operator precedence and opcode */
int op_first_chars[24] = {'+', '-', '*', '/', '%', '+', '-', '<', '>', '<', '>', '<', '>', '=', '!', '&', '|', '&', '^', '|', '~', '!', '*', 0};
int op_second_chars[24] = {'+', '-', '@', '@', '@', '@', '@', '<', '>', '=', '=', '@', '@', '=', '=', '&', '|', '@', '@', '@', '@', '@', '@', 0};
int op_precedences[24] = {11, 11, 1, 1, 1, 2, 2, 3, 3, 4, 4, 4, 4, 5, 5, 9, 10, 6, 7, 8, 2, 2, 0, 0};
int op_codes[24] = {0x0001, 0x00ff, 0xc1af0f, 0xf9f79991, 0xf9f79991, 0xc801, 0xd8f7c829, 0xe0d391, 0xf8d391, 0x000e, 0x000d, 0x000c, 0x000f, 0x0004, 0x0005, 0x0000, 0x0001, 0xc821, 0xc831, 0xc809, 0xd0f7, 0x0004, 0x0000, 0x0000};

/* 
allocate 99999Byte in Heap, using calloc 
--> sym_stack string
--> machine code buffer
--> variable table
*/
#define ALLOC_SIZE 99999
#define ELFOUT

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

/* additionnal elf output defines */
#ifdef ELFOUT

#define ELF_BASE      0x08048000
#define PHDR_OFFSET   0x30

#define INTERP_OFFSET 0x90
#define INTERP_SIZE   0x13

#ifndef TINY
#define DYNAMIC_OFFSET (INTERP_OFFSET + INTERP_SIZE + 1)
#define DYNAMIC_SIZE   (11*8)

#define ELFSTART_SIZE  (DYNAMIC_OFFSET + DYNAMIC_SIZE)
#else
#define DYNAMIC_OFFSET 0xa4
#define DYNAMIC_SIZE   0x58

#define ELFSTART_SIZE  0xfc
#endif

/* size of startup code */
#define STARTUP_SIZE   17

/* size of library names at the start of the .dynstr section */
#define DYNSTR_BASE      22

#endif

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
    int left, ahead; 

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
        identifier_last = sym_stack_current_ptr;
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
            /* 
                from complex, compressed string 
                to simple, multiple array (op_first_chars, op_second_chars, op_precedence, op_codes) 
                --> result: use more text segments.. but more simple
            */
            int i = 0;
            while (op_first_chars[i] != 0) {
               if (op_first_chars[i] == tok & (op_second_chars[i] == ch | op_second_chars[i] == '@')) {
                    tok_level = op_precedences[i];
                    tok_constant = op_codes[i];
                
                    if (op_second_chars[i] == ch) {
                        read_ch();
                        tok = TOK_DUMMY;
                    }
                    break;
               }
              i++;
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
        *(char *)text_segment_current++ = bytes;
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
/* read 32bit little-endian word from memory address */
read_word_from_addr(addr)
{
    /* first 1 byte (LSB)*/
    int byte0 = *(char *)addr & 0xff;
    int byte1 = (*(char *)(addr + 1) & 0xff) << 8;
    int byte2 = (*(char *)(addr + 2) & 0xff) << 16;
    int byte3 = (*(char *)(addr + 3) & 0xff) << 24;

    return byte3 | byte2 | byte1 | byte0;
}

/*  
    patch symbol reference 
    because our compiler has 1 pass
    We should resolve forward reference by back patching

    when we met 'return' statement, 
    we should read all of that function
    to know where the function ends.
    doing so, we can patch that unresolved symbol
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
           if (sym_position >= data_segment_start && sym_position < data_segment_current) 
                 /* if symbol exists in data_segment_start segment */
                add_word_to_addr(addr, sym_position + data_offset);
            else
                /* if symbol exists in text segment */
                add_word_to_addr(addr, sym_position - text_segment_start + text + data_offset);
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
    add_word_to_addr(text_segment_current, addr);
    /* address we appended right before */
    addr = text_segment_current;
    text_segment_current = text_segment_current + 4;

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

parse_unary_expr(l)
{

    /* TODO: refactor local variable's name again */
    int expr_type, tmp_tok, tmp_tok_constant, tmp_tok_level;

    /* type of expression 0 = forward, 1 = value, other = lvalue */
    expr_type = 1; /* default value = 1 ==> expression as value */

    /* parse string literal */
    if (tok == '\"') {
        /* load string literal's **address** to %eax */
        load_immediate(data_segment_current + data_offset);
        while (ch != '\"') {
            process_escape();
            *(char *)data_segment_current++ = ch;
            read_ch();
        }
        /* insert terminating symbol to end of string*/
        *(char *)data_segment_current = 0;

        /* 
            align 4 bytes boundary 
            -4 = 11111....11100 (2's complement)
            1. if data_segment_current = 5 --> ....00101
            2. data_segment_current + 4 = 9 --> ...01001
            3. & -4 = ...1000 = 8 
            --> 5바이트까지 차지했네..  다음엔 8에서 시작한다
        */
        data_segment_current = data_segment_current + 4 & -4;
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
            parse_entire_expr();
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

            /* dereference *ptr = value */
            if (tok == '=') { 
                read_token();
                /* %eax has pointer address */
                generate_machine_code(0x50); /* push %eax */
                /* parsing value */
                parse_entire_expr();
                generate_machine_code(0x59); /* pop %ecx */
                /*
                    movl %eax/%al, (%ecx) 
                    if tok type == INT --> store 4bytes(%eax)
                    else               --> store 1bytes(%al)
                 */
                
                generate_machine_code(0x0188 + (tmp_tok == TOK_INT)); 
            } else if (tmp_tok) {
                if (tmp_tok == TOK_INT)
                    /* store 4byte*/
                    generate_machine_code(0x8b);
                else
                    generate_machine_code(0xbe0f); /* movsbl (%eax), %(eax) */
                text_segment_current++; /* add zero in code */
            }
        } else if (tmp_tok == '&') {
            generate_move(10, tok); /* leal EA, %eax */
            read_token();
        } else {
            expr_type = 0;
            if (tok == '=' & l) {
                /* assignment */
                read_token();
                parse_entire_expr();
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
            parse_entire_expr();
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

parse_binary_expr(level)
{
    int op_value, tmp_tok, jump_chain;
    if (level-- == 1)
        parse_unary_expr(1);
    else {
        parse_binary_expr(level);
        jump_chain = 0;
        while (level == tok_level) {
            tmp_tok = tok;
            op_value = tok_constant;
            read_token();
            
            if (level > 8) {
                jump_chain = generate_cond_jump(op_value, jump_chain);
                parse_binary_expr(level);
            } else {
                /* operand1 to stack */
                generate_machine_code(0x50); /* push %eax */
                /* parse operand2 and store to %eax */
                parse_binary_expr(level);
                /* operand1 to %ecx */
                generate_machine_code(0x59); /* pop %ecx */

                if (level == 4 | level == 5) {
                    generate_compare(op_value);
                } else {
                    generate_machine_code(op_value);
                    if (tmp_tok == '%') 
                        generate_machine_code(0x92); /* xchg %edx %eax */
                }
            }
        }

        /* && and || output code generation */
        /* if jump_chain exists, tok_level > 8 --> &&, ||*/
        if (jump_chain && level > 8) {
            /* return 'new' jump instruction's address */
            jump_chain = generate_cond_jump(op_value, jump_chain);
            /* if op_value = 0 --> 1, 1 --> 0 */
            load_immediate(op_value ^ 1);
            /* 
                unconditional jump, current_position + 5
                skip 2 forward instructions
            */
            generate_jump(5); 
            patch_symbol_ref(jump_chain, text_segment_current);
            load_immediate(op_value);
            /*
                for example, a && b
                if a has false, executes conditional jump, result--> op_value^1
                if a has true, b has false, conditional jump, result --> op_value ^ 1
                if a,b both have true, do not execute cond jump, result --> op_value
            */
        }
    }
}

parse_entire_expr()
{
    parse_binary_expr(11);
}

parse_cond_expr()
{
    parse_entire_expr();
    return generate_cond_jump(0, 0);
}

parse_block(l)
{
    int cond_jump_addr, jump_addr, tmp_tok;

    if (tok == TOK_IF) {
        read_token();
        skip('(');
        /* generate cond jump if condition is false --> to else block */
        cond_jump_addr = parse_cond_expr();
        skip(')');
        parse_block(l);
        if (tok == TOK_ELSE) {
            read_token();
            /* don't know destination, patch it later */
            jump_addr = generate_jump(0);
            patch_symbol_ref(cond_jump_addr, text_segment_current); /* patch else jmp */
            /* parse else block */
            parse_block(l);
            /* patch destination --> end of else block */
            patch_symbol_ref(jump_addr, text_segment_current); /* patch if test */
        } else {
            /* patch don't know address --> after if block */
            patch_symbol_ref(cond_jump_addr, text_segment_current);
        }
    } else if (tok == TOK_WHILE | tok == TOK_FOR) {
        tmp_tok = tok;
        read_token();
        skip('(');
        if (tmp_tok == TOK_WHILE) {
            /* start of while loop address */
            jump_addr = text_segment_current;
            /*  parse condition, generate cond jump, 
                we'll be redirected to this address
                if we have false condition
            */
            cond_jump_addr = parse_cond_expr();
        } else {
            /* for (a = 1; */
            if (tok != ';') 
                parse_entire_expr();
            skip(';');

            /* address of condition checking, in loop */
            jump_addr = text_segment_current;
            /* address generates if condition has false */
            cond_jump_addr = 0;
            if (tok != ';')
                cond_jump_addr = parse_cond_expr();
            skip(';');

            /* parsing increment in for (.... ; i = i + 1) */
            if (tok != ')') {
                tmp_tok = generate_jump(0);
                parse_entire_expr();
                /* go back to conditional check.. */
                generate_jump(jump_addr - text_segment_current - 5);
                patch_symbol_ref(tmp_tok, text_segment_current);
                jump_addr = tmp_tok + 4;
            }
        }
        skip(')');
        parse_block(&cond_jump_addr);
        generate_jump(jump_addr - text_segment_current - 5);
        patch_symbol_ref(cond_jump_addr, text_segment_current);
    } else if (tok == '{') {
        read_token();
        /* declaration (local variables )*/
        parse_decl(1);
        while (tok != '}')
            parse_block(l);
        read_token();
    } else {
        if (tok == TOK_RETURN) {
            read_token();
            if (tok != ';')
                parse_entire_expr();
            ra_list = generate_jump(ra_list);
        } else if (tok == TOK_BREAK) {
            read_token();
            *(int *)l = generate_jump(*(int *)l);
        } else if (tok != ';') 
            parse_entire_expr();
        skip(';');
    }
}

/* l is true if local declaration */
parse_decl(l)
{
    int arg_offset;

    while (tok == TOK_INT | tok != -1 & !l) {
        if (tok == TOK_INT) {
            read_token();
            while (tok != ';') {
                if (l) {
                    /* process local variable */
                    var_local_offset = var_local_offset + 4;
                    *(int *)tok = -var_local_offset;
                } else {
                    *(int *)tok = data_segment_current;
                    data_segment_current = data_segment_current + 4;
                }
                read_token();
                if (tok == ',')
                    read_token();
            }
            skip(';');
        } else { /* parse function declaration */
            /* put function address */
            *(int *)tok = text_segment_current;
            read_token();
            skip('(');
            /*
            [EBP+0] = previous EBP value 
            [EBP+4] = return address 
            [EBP+8] = 1st arguments  
            */
            arg_offset = 8; /* for 1st arguments */
            while (tok != ')') {
                /* read args name and compute offset */
                *(int *)tok = arg_offset;
                arg_offset = arg_offset + 4; /* for other args */
                read_token();
                if (tok == ',')
                    read_token();
            }
            read_token(); /* skip ')' */
            ra_list = var_local_offset = 0;
            /* prologue */
            generate_machine_code(0xe58955); /* push %ebp, mov %esp, %ebp */
            /* save to 'arg_offset' for patching */
            arg_offset = generate_machine_code_with_addr(0xec81, 0); /* sub $xxx, %esp */
            parse_block(0);
            patch_symbol_ref(ra_list, text_segment_current);
            generate_machine_code(0xc3c9);
            /* patch $xxx in sub $xxx, %esp with local var's offset */
            add_word_to_addr(arg_offset, var_local_offset);
        }
    }
}

#ifdef ELFOUT

elf_generate_little_endian_32(addr)
{
    add_word_to_addr(data_segment_current, addr);
    data_segment_current = data_segment_current + 4;
}

/* used to generate a program header at offset 'n' of size 't' */
elf_generate_program_header(n, t)
{
    elf_generate_little_endian_32(n);
    n = n + ELF_BASE;
    elf_generate_little_endian_32(n);
    elf_generate_little_endian_32(n);
    elf_generate_little_endian_32(t);
    elf_generate_little_endian_32(t);
}

/* use to relocate symbols that has not been resolved (because of forward reference) */
elf_reloc(l)
{
    /* 
        - During iterate symbol stack, check if this symbol is 'forward referenced'
        - Extract symbol's name/info, and Relocate the symbol into proper section
        
        pos: currently processing symbol's position in symbol stack
        sym_name_ptr: current symbol name's addr
        sym_ref_list: current symbol's reference list 
        sym_offset: symbol offset / index
        sym_value: symbol's value (addr or state)
        sym_type_flag: relocate type flag (0: absolute address, 1: relative address)
    */
    int pos, sym_name_ptr, sym_ref_list, sym_offset, sym_value, sym_type_flag;

    sym_offset = 0;
    pos = sym_stack_start_ptr;
    while (1) {
        /* extract symbol name */
        pos++;
        sym_name_ptr = pos;
        while (*(char *)pos != TAG_TOK && pos < sym_stack_current_ptr)
            pos++;
        if (pos == sym_stack_current_ptr)
            break;
        /* now see if it is forward defined */
        tok = var_table + (sym_name_ptr - sym_stack_start_ptr) * 8 + TOK_IDENT - 8;
        /* deref , and extract symbol's value  */
        sym_value = *(int *)tok;
        sym_ref_list = *(int *)(tok + 4);
        /* if !sym_value, this symbol is not defined(external symbol) */
        if (sym_ref_list && !sym_value) {
            if (!sym_value) {
                if (!l) {
                    /* symbol string(copy symbol's name to dynstr table) */
                    memcpy(data_segment_current, sym_name_ptr, pos - sym_name_ptr);
                    data_segment_current = data_segment_current + pos - sym_name_ptr + 1; /* add a zero */
                } else if (l == 1) {
                    /* symbol table .dynsym */
                    elf_generate_little_endian_32(sym_offset + DYNSTR_BASE);
                    elf_generate_little_endian_32(0);
                    elf_generate_little_endian_32(0);
                    elf_generate_little_endian_32(0x10); /* STB_GLOBAL, STT_NOTYPE */
                    sym_offset = sym_offset + pos - sym_name_ptr + 1; /* add a zero */
                } else {
                    /* .rel.text */
                    sym_offset++;
                    /* generate relocation patches */
                    while (sym_ref_list) {
                        sym_name_ptr = read_word_from_addr(sym_ref_list);
                        /* sym_type_flag = 0: R_386_32, c = 1: R_386_PC32 */
                        sym_type_flag = *(char *)(sym_ref_list - 1) != 0x05;
                        add_word_to_addr(sym_ref_list, -sym_type_flag * 4);
                        /* record relocate position */
                        elf_generate_little_endian_32(sym_ref_list - text_segment_start + text + data_offset);
                        /* record relocate info R_386_32 / R_386_PC32*/
                        elf_generate_little_endian_32(sym_offset * 256 + sym_type_flag + 1);
                        sym_ref_list = sym_name_ptr;
                    }
                }
            } else if (!l) {
                /* generate standard relocation */
                patch_symbol_ref(sym_ref_list, sym_value);
            }
        }
    }
}

elf_out(c)
{
    int glo_saved, dynstr, dynstr_size, dynsym, hash, rel, n, t, text_size;

    /*****************************/
    /* add text segment (but copy it later to handle relocations) */
    text = data_segment_current;
    text_size = text_segment_current - text_segment_start;

    /* add the startup code */
    text_segment_current = text_segment_start;
    generate_machine_code(0x505458); /* pop %eax, push %esp, push %eax */
    t = *(int *)(var_table + TOK_MAIN);
    generate_machine_code_with_addr(0xe8, t - text_segment_current - 5);
    generate_machine_code(0xc389);  /* movl %eax, %ebx */
    load_immediate(1);      /* mov $1, %eax */
    generate_machine_code(0x80cd);  /* int $0x80 */
    data_segment_current = data_segment_current + text_size;

    /*****************************/
    /* add symbol strings */
    dynstr = data_segment_current;
    /* libc name for dynamic table */
    data_segment_current++;
    data_segment_current = strcpy(data_segment_current, "libc.so.6") + 10;
    data_segment_current = strcpy(data_segment_current, "libdl.so.2") + 11;
    
    /* export all forward referenced functions */
    elf_reloc(0);
    dynstr_size = data_segment_current - dynstr;

    /*****************************/
    /* add symbol table */
    data_segment_current = (data_segment_current + 3) & -4;
    dynsym = data_segment_current;
    elf_generate_little_endian_32(0);
    elf_generate_little_endian_32(0);
    elf_generate_little_endian_32(0);
    elf_generate_little_endian_32(0);
    elf_reloc(1);

    /*****************************/
    /* add symbol hash table */
    hash = data_segment_current;
    n = (data_segment_current - dynsym) / 16;
    elf_generate_little_endian_32(1); /* one bucket (simpler!) */
    elf_generate_little_endian_32(n);
    elf_generate_little_endian_32(1);
    elf_generate_little_endian_32(0); /* dummy first symbol */
    t = 2;
    while (t < n)
        elf_generate_little_endian_32(t++);
    elf_generate_little_endian_32(0);
    
    /*****************************/
    /* relocation table */
    rel = data_segment_current;
    elf_reloc(2);

    /* copy code AFTER relocation is done */
    memcpy(text, text_segment_start, text_size);

    glo_saved = data_segment_current;
    data_segment_current = data_segment_start;

    /* elf header */
    elf_generate_little_endian_32(0x464c457f);
    elf_generate_little_endian_32(0x00010101);
    elf_generate_little_endian_32(0);
    elf_generate_little_endian_32(0);
    elf_generate_little_endian_32(0x00030002);
    elf_generate_little_endian_32(1);
    elf_generate_little_endian_32(text + data_offset); /* address of _start */
    elf_generate_little_endian_32(PHDR_OFFSET); /* offset of phdr */
    elf_generate_little_endian_32(0);
    elf_generate_little_endian_32(0);
    elf_generate_little_endian_32(0x00200034);
    elf_generate_little_endian_32(3); /* phdr entry count */

    /* program headers */
    elf_generate_little_endian_32(3); /* PT_INTERP */
    elf_generate_program_header(INTERP_OFFSET, INTERP_SIZE);
    elf_generate_little_endian_32(4); /* PF_R */
    elf_generate_little_endian_32(1); /* align */
    
    elf_generate_little_endian_32(1); /* PT_LOAD */
    elf_generate_program_header(0, glo_saved - data_segment_start);
    elf_generate_little_endian_32(7); /* PF_R | PF_X | PF_W */
    elf_generate_little_endian_32(0x1000); /* align */
    
    elf_generate_little_endian_32(2); /* PT_DYNAMIC */
    elf_generate_program_header(DYNAMIC_OFFSET, DYNAMIC_SIZE);
    elf_generate_little_endian_32(6); /* PF_R | PF_W */
    elf_generate_little_endian_32(0x4); /* align */

    /* now the interpreter name */
    data_segment_current = strcpy(data_segment_current, "/lib/ld-linux.so.2") + 0x14;

    /* now the dynamic section */
    elf_generate_little_endian_32(1); /* DT_NEEDED */
    elf_generate_little_endian_32(1); /* libc name */
    elf_generate_little_endian_32(1); /* DT_NEEDED */
    elf_generate_little_endian_32(11); /* libdl name */
    elf_generate_little_endian_32(4); /* DT_HASH */
    elf_generate_little_endian_32(hash + data_offset);
    elf_generate_little_endian_32(6); /* DT_SYMTAB */
    elf_generate_little_endian_32(dynsym + data_offset);
    elf_generate_little_endian_32(5); /* DT_STRTAB */
    elf_generate_little_endian_32(dynstr + data_offset);
    elf_generate_little_endian_32(10); /* DT_STRSZ */
    elf_generate_little_endian_32(dynstr_size);
    elf_generate_little_endian_32(11); /* DT_SYMENT */
    elf_generate_little_endian_32(16);
    elf_generate_little_endian_32(17); /* DT_REL */
    elf_generate_little_endian_32(rel + data_offset);
    elf_generate_little_endian_32(18); /* DT_RELSZ */
    elf_generate_little_endian_32(glo_saved - rel);
    elf_generate_little_endian_32(19); /* DT_RELENT */
    elf_generate_little_endian_32(8);
    elf_generate_little_endian_32(0);  /* DT_NULL */
    elf_generate_little_endian_32(0);

    /* write binary */
    t = fopen(c, "w");
    fwrite(data_segment_start, 1, glo_saved - data_segment_start, t);
    fclose(t);
}
#endif

main(n, t)
{
    if (n < 3) {
        printf("usage: otccelf file.c outfile\n");
        return 0;
    }
    sym_stack_current_ptr = strcpy(sym_stack_start_ptr = calloc(1, ALLOC_SIZE), 
                  " int if else while break return for define main ") + TOK_STR_SIZE;
    data_segment_current = data_segment_start = calloc(1, ALLOC_SIZE);
    text_segment_current = text_segment_start = calloc(1, ALLOC_SIZE);
    var_table = calloc(1, ALLOC_SIZE);

    t = t + 4;
    file_ptr = fopen(*(int *)t, "r");

    data_offset = ELF_BASE - data_segment_start; 
    data_segment_current = data_segment_current + ELFSTART_SIZE;
    text_segment_current = text_segment_current + STARTUP_SIZE;

    read_ch();
    read_token();
    parse_decl(0);
    t = t + 4;
    elf_out(*(int *)t);
    return 0;
}