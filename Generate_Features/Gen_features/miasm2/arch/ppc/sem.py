import miasm2.expression.expression as expr
from miasm2.ir.ir import AssignBlock, IntermediateRepresentation, IRBlock
from miasm2.arch.ppc.arch import mn_ppc
from miasm2.arch.ppc.regs import *
from miasm2.core.sembuilder import SemBuilder
from miasm2.jitter.csts import *

spr_dict = {
    8: LR, 9: CTR, 18: DSISR, 19: DAR,
    22: DEC, 26: SRR0, 27: SRR1,
    272: SPRG0, 273: SPRG0, 274: SPRG1, 275: SPRG2, 276: SPRG3,
    284: TBL, 285: TBU, 287: PVR, 1023: PIR
}

crf_dict = dict((ExprId("CR%d" % i, 4),
                 dict( (bit, ExprId("CR%d_%s" % (i, bit), 1))
                       for bit in ['LT', 'GT', 'EQ', 'SO' ] ))
                for i in xrange(8) )

ctx = { 'crf_dict': crf_dict, 'spr_dict': spr_dict }
ctx.update(all_regs_ids_byname)
sbuild = SemBuilder(ctx)

def mn_compute_flags(rvalue, overflow_expr=None):
    ret = []
    ret.append(ExprAff(CR0_LT, rvalue.msb()))
    ret.append(ExprAff(CR0_GT, (ExprCond(rvalue, ExprInt(1, 1),
                                         ExprInt(0, 1)) & ~rvalue.msb())))
    ret.append(ExprAff(CR0_EQ, ExprCond(rvalue, ExprInt(0, 1),
                                        ExprInt(1, 1))))
    if overflow_expr != None:
        ret.append(ExprAff(CR0_SO, XER_SO | overflow_expr))
    else:
        ret.append(ExprAff(CR0_SO, XER_SO))

    return ret

def mn_do_add(ir, instr, arg1, arg2, arg3):
    assert instr.name[0:3] == 'ADD'

    flags_update = []

    has_dot = False
    has_c = False
    has_e = False
    has_o = False

    for l in instr.name[3:]:
        if l == '.':
            has_dot = True
        elif l == 'C':
            has_c = True
        elif l == 'E':
            has_e = True
        elif l == 'O':
            has_o = True
        elif l == 'I' or l == 'M' or l == 'S' or l == 'Z':
            pass	# Taken care of earlier
        else:
            assert False

    rvalue = arg2 + arg3

    if has_e:
        rvalue = rvalue + XER_CA.zeroExtend(32)

    over_expr = None
    if has_o:
        msb1 = arg2.msb()
        msb2 = arg3.msb()
        msba = rvalue.msb()
        over_expr = ~(msb1 ^ msb2) & (msb1 ^ msba)
        flags_update.append(ExprAff(XER_OV, over_expr))
        flags_update.append(ExprAff(XER_SO, XER_SO | over_expr))

    if has_dot:
        flags_update += mn_compute_flags(rvalue, over_expr)

    if has_c or has_e:
        carry_expr = (((arg2 ^ arg3) ^ rvalue) ^
                      ((arg2 ^ rvalue) & (~(arg2 ^ arg3)))).msb()
        flags_update.append(ExprAff(XER_CA, carry_expr))

    return ([ ExprAff(arg1, rvalue) ] + flags_update), []

def mn_do_and(ir, instr, ra, rs, arg2):
    if len(instr.name) > 3 and instr.name[3] == 'C':
        oarg = ~arg2
    else:
        oarg = arg2

    rvalue = rs & oarg
    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_cntlzw(ir, instr, ra, rs):
    ret = [ ExprAff(ra, ExprOp('cntleadzeros', rs)) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def crbit_to_reg(bit):
    bit = bit.arg.arg
    crid = bit / 4
    bitname = [ 'LT', 'GT', 'EQ', 'SO' ][bit % 4]
    return all_regs_ids_byname["CR%d_%s" % (crid, bitname)]

def mn_do_cr(ir, instr, crd, cra, crb):
    a = crbit_to_reg(cra)
    b = crbit_to_reg(crb)
    d = crbit_to_reg(crd)

    op = instr.name[2:]

    if op == 'AND':
        r = a & b
    elif op == 'ANDC':
        r = a & ~b
    elif op == 'EQV':
        r = ~(a ^ b)
    elif op == 'NAND':
        r = ~(a & b)
    elif op == 'NOR':
        r = ~(a | b)
    elif op == 'OR':
        r = a | b
    elif op == 'ORC':
        r = a | ~b
    elif op == 'XOR':
        r = a ^ b
    else:
        raise "Unknown operation on CR"
    return [ ExprAff(d, r) ], []

def mn_do_div(ir, instr, rd, ra, rb):
    assert instr.name[0:4] == 'DIVW'

    flags_update = []

    has_dot = False
    has_c = False
    has_o = False
    has_u = False

    for l in instr.name[3:]:
        if l == '.':
            has_dot = True
        elif l == 'C':
            has_c = True
        elif l == 'O':
            has_o = True
        elif l == 'U':
            has_u = True
        elif l == 'W':
            pass
        else:
            assert False

    if has_u:
        op = 'udiv'
    else:
        op = 'idiv'

    rvalue = ExprOp(op, ra, rb)

    over_expr = None
    if has_o:
        over_expr = ExprCond(rb, ExprInt(0, 1), ExprInt(1, 1))
        if not has_u:
            over_expr = over_expr | (ExprCond(ra ^ 0x80000000, ExprInt(0, 1),
                                              ExprInt(1, 1)) &
                                     ExprCond(rb ^ 0xFFFFFFFF, ExprInt(0, 1),
                                              ExprInt(1, 1)))
        flags_update.append(ExprAff(XER_OV, over_expr))
        flags_update.append(ExprAff(XER_SO, XER_SO | over_expr))

    if has_dot:
        flags_update += mn_compute_flags(rvalue, over_expr)

    return ([ ExprAff(rd, rvalue) ] + flags_update), []
    

def mn_do_eqv(ir, instr, ra, rs, rb):
    rvalue = ~(rs ^ rb)
    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_exts(ir, instr, ra, rs):
    if instr.name[4] == 'B':
        size = 8
    elif instr.name[4] == 'H':
        size = 16
    else:
        assert False

    rvalue = rs[0:size].signExtend(32)
    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def byte_swap(expr):
    nbytes = expr.size / 8
    bytes = [ expr[i*8:i*8+8] for i in xrange(nbytes - 1, -1, -1) ]
    # str(bytes) = [
    #   ExprSlice(ExprMem(ExprOp('+', ExprInt(0x0, 32), ExprId('R4', 32)), 32), 24, 32),
    #   ExprSlice(ExprMem(ExprOp('+', ExprInt(0x0, 32), ExprId('R4', 32)), 32), 16, 24),
    #   ExprSlice(ExprMem(ExprOp('+', ExprInt(0x0, 32), ExprId('R4', 32)), 32), 8, 16),
    #   ExprSlice(ExprMem(ExprOp('+', ExprInt(0x0, 32), ExprId('R4', 32)), 32), 0, 8)
    # ]
    # with open("G:\\VulSeeker\\VulSeeker\\ppc_sem_mm_do_load_assert.txt", "a") as f:
    #     a = [type(byte) for byte in bytes]
    #     f.write(str(a) + '\n')
    #     f.write(str(bytes) + '\n')
    return ExprCompose(*bytes)

def mn_do_load(ir, instr, arg1, arg2, arg3=None):
    assert instr.name[0] == 'L'

    ret = []

    if instr.name[1] == 'M':
        return mn_do_lmw(ir, instr, arg1, arg2)
    elif instr.name[1] == 'S':
        return mn_do_lswi(ir, instr, arg1, arg2, arg3)
        # raise RuntimeError("LSWI, and LSWX need implementing")
        pass # XXX

    size = {'B': 8, 'H': 16, 'W': 32}[instr.name[1]]

    has_a = False
    has_b = False
    has_u = False
    is_lwarx = False
    is_lwbrx = False

    for l in instr.name[2:]:
        if l == 'A':
            has_a = True
        elif l == 'B':
            has_b = True
        elif l == 'U':
            has_u = True
        elif l == 'X' or l == 'Z':
            pass	# Taken care of earlier
        elif l == 'R':
            if not has_b:
                is_lwarx = True
            else:
                is_lwbrx = True
        else:
            # with open("G:\\VulSeeker\\VulSeeker\\ppc_sem_mm_do_load_assert.txt", "w") as f:
            #     f.write(str(type(ir)) + '\n')
            #     f.write(str(ir) + '\n')
            #     f.write(str(type(instr)) + '\n')
            #     f.write(str(instr) + '\n')
            #     f.write(str(instr.name) + '\n')
            #     f.write(str(type(arg1)) + '\n')
            #     f.write(str(arg1) + '\n')
            #     f.write(str(type(arg2)) + '\n')
            #     f.write(str(arg2) + '\n')
            #     f.write(str(arg3) + '\n')
            assert False
    # with open("G:\\VulSeeker\\VulSeeker\\ppc_sem_mm_do_load_assert.txt", "a") as f:
    #     f.write(str(type(ir)) + '\n')
    #     f.write(str(ir) + '\n')
    #     f.write(str(type(instr)) + '\n')
    #     f.write(str(instr) + '\n')
    #     f.write(str(instr.name) + '\n')
    #     f.write(str(type(arg1)) + '\n')
    #     f.write(str(arg1) + '\n')
    #     f.write(str(type(arg2)) + '\n')
    #     f.write(str(arg2) + '\n')
    #     f.write(str(type(arg3)) + '\n')
    #     f.write(str(arg3) + '\n')
    if arg3 is None:
        assert isinstance(arg2, ExprMem)

        address = arg2.arg
    else:
        address = arg2 + arg3
    # with open("G:\\VulSeeker\\VulSeeker\\ppc_sem_mm_do_load_assert.txt", "w") as f:
    #     f.write(str(type(address)) + '\n')
    #     f.write(str(address) + '\n')
    src = ExprMem(address, size)

    if has_b:
        src = byte_swap(src)

    if has_a:
        src = src.signExtend(32)
    else:
        src = src.zeroExtend(32)

    ret.append(ExprAff(arg1, src))
    if has_u:
        if arg3 is None:
            ret.append(ExprAff(arg2.arg.args[0], address))
        else:
            ret.append(ExprAff(arg2, address))

    if is_lwarx:
        ret.append(ExprAff(reserve, ExprInt(1, 1)))
        ret.append(ExprAff(reserve_address, address))	# XXX should be the PA

    return ret, []

def mn_do_lmw(ir, instr, rd, src):
    ret = []
    address = src.arg
    ri = int(rd.name[1:], 10)
    i = 0
    while ri <= 31:
        ret.append(ExprAff(all_regs_ids_byname["R%d" % ri],
                           ExprMem(address + ExprInt(i, 32), 32)))
        ri += 1
        i += 4

    return ret, []

def mn_do_lswi(ir, instr, rd, ra, nb):
    if nb == 0:
        nb = 32
    else:
        nb = int(nb)
    ret = []
    address = ra
    ri = int(rd.name[1:],10)
    # with open('G:\\test.txt', 'w') as fp:
    #     fp.write(str(ri) + '\n')
    #     fp.write(str(nb) + '\n')
    #     fp.write(str(address) + '\n')
    i = 0
    while i < nb:
        # with open('G:\\test2.txt', 'a') as fp:
        #     fp.write(str(i) + '\n')
        #     fp.write(str(int(nb)) + '\n')
        #     fp.write(str(ri) + '\n\n')
        ret.append(ExprAff(all_regs_ids_byname["R%d" % ri],
                           ExprMem(address + ExprInt(i, 32), 32)))
        ri += 1
        i += 4
    return ret, []
    # raise "%r not implemented" % instr

def mn_do_lswx(ir, instr, rd, ra, nb):
    raise "%r not implemented" % instr

def mn_do_mcrf(ir, instr, crfd, crfs):
    ret = []

    for bit in [ 'LT', 'GT', 'EQ', 'SO' ]:
        d = all_regs_ids_byname["%s_%s" % (crfd, bit)]
        s = all_regs_ids_byname["%s_%s" % (crfs, bit)]
        ret.append(ExprAff(d, s))

    return ret, []

def mn_do_mcrxr(ir, instr, crfd):
    ret = []

    for (bit, val) in [ ('LT', XER_SO), ('GT', XER_OV), ('EQ', XER_CA),
                        ('SO', ExprInt(0, 1)) ]:
        ret.append(ExprAff(all_regs_ids_byname["%s_%s" % (crfd, bit)], val))

    return ret, []

def mn_do_mfcr(ir, instr, rd):
    return ([ ExprAff(rd, ExprCompose(*[ all_regs_ids_byname["CR%d_%s" % (i, b)]
                                        for i in xrange(7, -1, -1)
                                        for b in ['SO', 'EQ', 'GT', 'LT']]))],
            [])

@sbuild.parse
def mn_mfmsr(rd):
    rd = MSR

def mn_mfspr(ir, instr, arg1, arg2):
    sprid = arg2.arg.arg
    gprid = int(arg1.name[1:])
    if sprid in spr_dict:
        return [ ExprAff(arg1, spr_dict[sprid]) ], []
    elif sprid == 1:		# XER
        return [ ExprAff(arg1, ExprCompose(XER_BC, ExprInt(0, 22),
                                           XER_CA, XER_OV, XER_SO)) ], []
    else:
        return [ ExprAff(spr_access,
                         ExprInt(((sprid << SPR_ACCESS_SPR_OFF) |
                                    (gprid << SPR_ACCESS_GPR_OFF)), 32)),
                 ExprAff(exception_flags, ExprInt(EXCEPT_SPR_ACCESS, 32)) ], []

def mn_mtcrf(ir, instr, crm, rs):
    ret = []

    for i in xrange(8):
        if crm.arg.arg & (1 << (7 - i)):
            j = (28 - 4 * i) + 3
            for b in ['LT', 'GT', 'EQ', 'SO']:
                ret.append(ExprAff(all_regs_ids_byname["CR%d_%s" % (i, b)],
                                   rs[j:j+1]))
                j -= 1

    return ret, []

def mn_mtmsr(ir, instr, rs):
    print "%08x: MSR assigned" % instr.offset
    return [ ExprAff(MSR, rs) ], []

def mn_mtspr(ir, instr, arg1, arg2):
    sprid = arg1.arg.arg
    gprid = int(arg2.name[1:])
    if sprid in spr_dict:
        return [ ExprAff(spr_dict[sprid], arg2) ], []
    elif sprid == 1:		# XER
        return [ ExprAff(XER_SO, arg2[31:32]),
                 ExprAff(XER_OV, arg2[30:31]),
                 ExprAff(XER_CA, arg2[29:30]),
                 ExprAff(XER_BC, arg2[0:7]) ], []
    else:
        return [ ExprAff(spr_access,
                         ExprInt(((sprid << SPR_ACCESS_SPR_OFF) |
                                    (gprid << SPR_ACCESS_GPR_OFF) |
                                    SPR_ACCESS_IS_WRITE), 32)),
                 ExprAff(exception_flags, ExprInt(EXCEPT_SPR_ACCESS, 32)) ], []

def mn_do_mul(ir, instr, rd, ra, arg2):
    variant = instr.name[3:]
    if variant[-1] == '.':
        variant = variant[:-2]

    if variant == 'HW':
        v1 = ra.signExtend(64)
        v2 = arg2.signExtend(64)
        shift = 32
    elif variant == 'HWU':
        v1 = ra.zeroExtend(64)
        v2 = arg2.zeroExtend(64)
        shift = 32
    else:
        v1 = ra
        v2 = arg2
        shift = 0

    rvalue = ExprOp('*', v1, v2)
    if shift != 0:
        rvalue = rvalue[shift : shift + 32]

    ret = [ ExprAff(rd, rvalue) ]

    over_expr = None
    if variant[-1] == 'O':
        over_expr = ExprCond((rvalue.signExtend(64) ^
                              ExprOp('*', v1.signExtend(64),
                                     v2.signExtend(64))),
                             ExprInt(1, 1), ExprInt(0, 1))
        ret.append(ExprAff(XER_OV, over_expr))
        ret.append(ExprAff(XER_SO, XER_SO | over_expr))

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue, over_expr)

    return ret, []

def mn_do_nand(ir, instr, ra, rs, rb):
    rvalue = ~(rs & rb)
    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_neg(ir, instr, rd, ra):
    rvalue = -ra
    ret = [ ExprAff(rd, rvalue) ]
    has_o = False

    over_expr = None
    if instr.name[-1] == 'O' or instr.name[-2] == 'O':
        has_o = True
        over_expr = ExprCond(ra ^ ExprInt(0x80000000, 32),
                             ExprInt(0, 1), ExprInt(1, 1))
        ret.append(ExprAff(XER_OV, over_expr))
        ret.append(ExprAff(XER_SO, XER_SO | over_expr))

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue, over_expr)

    return ret, []

def mn_do_nor(ir, instr, ra, rs, rb):

    rvalue = ~(rs | rb)
    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_or(ir, instr, ra, rs, arg2):
    if len(instr.name) > 2 and instr.name[2] == 'C':
        oarg = ~arg2
    else:
        oarg = arg2

    rvalue = rs | oarg
    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_rfi(ir, instr):
    dest = ExprCompose(ExprInt(0, 2), SRR0[2:32])
    ret = [ ExprAff(MSR, (MSR &
                          ~ExprInt(0b1111111101110011, 32) |
                          ExprCompose(SRR1[0:2], ExprInt(0, 2),
                                      SRR1[4:7], ExprInt(0, 1), 
                                      SRR1[8:16], ExprInt(0, 16)))),
            ExprAff(PC, dest),
            ExprAff(ir.IRDst, dest) ]
    return ret, []

def mn_do_rotate(ir, instr, ra, rs, shift, mb, me):
    r = ExprOp('<<<', rs, shift)
    if mb <= me:
        m = ExprInt(((1 << (32 - mb)) - 1) & ~((1 << (32 - me - 1)) - 1), 32)
    else:
        m = ExprInt(((1 << (32 - mb)) - 1) | ~((1 << (32 - me - 1)) - 1), 32)
    rvalue = r & m
    if instr.name[0:6] == 'RLWIMI':
        rvalue = rvalue | (ra & ~m)

    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_slw(ir, instr, ra, rs, rb):

    rvalue = ExprCond(rb[5:6], ExprInt(0, 32),
                      ExprOp('<<', rs, rb & ExprInt(0b11111, 32)))
    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_sraw(ir, instr, ra, rs, rb):
    rvalue = ExprCond(rb[5:6], ExprInt(0xFFFFFFFF, 32),
                      ExprOp('a>>', rs, rb & ExprInt(0b11111, 32)))
    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    mask = ExprCond(rb[5:6], ExprInt(0xFFFFFFFF, 32),
                    (ExprInt(0xFFFFFFFF, 32) >>
                     (ExprInt(32, 32) - (rb & ExprInt(0b11111, 32)))))
    ret.append(ExprAff(XER_CA, rs.msb() &
                       ExprCond(rs & mask, ExprInt(1, 1), ExprInt(0, 1))))

    return ret, []

def mn_do_srawi(ir, instr, ra, rs, imm):
    rvalue = ExprOp('a>>', rs, imm)
    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    mask = ExprInt(0xFFFFFFFF >> (32 - imm.arg.arg), 32)

    ret.append(ExprAff(XER_CA, rs.msb() &
                       ExprCond(rs & mask, ExprInt(1, 1), ExprInt(0, 1))))

    return ret, []

def mn_do_srw(ir, instr, ra, rs, rb):
    rvalue = rs >> (rb & ExprInt(0b11111, 32))
    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_stmw(ir, instr, rs, dest):
    ret = []
    address = dest.arg
    ri = int(rs.name[1:],10)
    i = 0
    while ri <= 31:
        ret.append(ExprAff(ExprMem(address + ExprInt(i,32), 32),
                           all_regs_ids_byname["R%d" % ri]))
        ri += 1
        i += 4

    return ret, []

def mn_do_stswi(ir, instr, rd, ra, nb):
    if nb == 0:
        nb = 32
    else:
        nb = int(nb)
    ret = []
    address = ra
    ri = int(rd.name[1:],10)
    # with open('G:\\test.txt', 'w') as fp:
    #     fp.write(str(ri) + '\n')
    #     fp.write(str(nb) + '\n')
    #     fp.write(str(address) + '\n')
    i = 0
    while i < nb:
        # with open('G:\\test2.txt', 'a') as fp:
        #     fp.write(str(i) + '\n')
        #     fp.write(str(int(nb)) + '\n')
        #     fp.write(str(ri) + '\n\n')
        ret.append(ExprAff(ExprMem(address + ExprInt(i, 32), 32),
                           all_regs_ids_byname["R%d" % ri]))
        ri += 1
        i += 4
    return ret, []
    # raise "%r not implemented" % instr

def mn_do_store(ir, instr, arg1, arg2, arg3=None):
    assert instr.name[0:2] == 'ST'

    ret = []
    additional_ir = []

    if instr.name[2] == 'S':
        return mn_do_stswi(ir, instr, arg1, arg2, arg3)
        # raise RuntimeError("STSWI, and STSWX need implementing")
        pass # XXX

    size = {'B': 8, 'H': 16, 'W': 32}[instr.name[2]]

    has_b = False
    has_u = False
    is_stwcx = False

    for l in instr.name[3:]:
        if l == 'B' or l == 'R':
            has_b = True
        elif l == 'U':
            has_u = True
        elif l == 'X' or l == 'Z':
            pass	# Taken care of earlier
        elif l == 'C' or l == '.':
            is_stwcx = True
        else:
            assert False

    if arg3 is None:
        assert isinstance(arg2, ExprMem)

        address = arg2.arg
    else:
        address = arg2 + arg3

    dest = ExprMem(address, size)

    src = arg1[0:size]
    if has_b:
        src = byte_swap(src)

    # with open("G:\\VulSeeker\\VulSeeker\\ppc_sem_mm_do_load_assert.txt", "a") as f:
    #     f.write(str(type(ir)) + '\n')
    #     f.write(str(ir) + '\n')
    #     f.write(str(type(instr)) + '\n')
    #     f.write(str(instr) + '\n')
    #     f.write(str(instr.name) + '\n')
    #     f.write(str(type(arg1)) + '\n')
    #     f.write(str(arg1) + '\n')
    #     f.write(str(type(arg2)) + '\n')
    #     f.write(str(arg2) + '\n')
    #     f.write(str(type(arg3)) + '\n')
    #     f.write(str(arg3) + '\n')
    #     f.write(str(type(arg2.arg)) + '\n')
    #     f.write(str(arg2.arg) + '\n')
    #     f.write(str(type(arg2.arg.args[0])) + '\n')
    #     f.write(str(arg2.arg.args[0]) + '\n')
    ret.append(ExprAff(dest, src))
    if has_u:
        if arg3 is None:
            # original:
            # ret.append(ExprAff(arg2.arg.args[0], address))
            ret.append(ExprAff(arg2.arg, address))
        else:
            ret.append(ExprAff(arg2, address))

    if is_stwcx:
        lbl_do = ExprId(ir.gen_label(), ir.IRDst.size)
        lbl_dont = ExprId(ir.gen_label(), ir.IRDst.size)
        lbl_next = ExprId(ir.get_next_label(instr), ir.IRDst.size)
        flags = [ ExprAff(CR0_LT, ExprInt(0,1)),
                  ExprAff(CR0_GT, ExprInt(0,1)),
                  ExprAff(CR0_SO, XER_SO)]
        ret += flags
        ret.append(ExprAff(CR0_EQ, ExprInt(1,1)))
        ret.append(ExprAff(ir.IRDst, lbl_next))
        dont = flags + [ ExprAff(CR0_EQ, ExprInt(0,1)),
                         ExprAff(ir.IRDst, lbl_next) ]
        additional_ir = [ IRBlock(lbl_do.name, [ AssignBlock(ret) ]),
                          IRBlock(lbl_dont.name, [ AssignBlock(dont) ]) ]
        ret = [ ExprAff(reserve, ExprInt(0, 1)),
                ExprAff(ir.IRDst, ExprCond(reserve, lbl_do, lbl_dont)) ]

    return ret, additional_ir

def mn_do_sub(ir, instr, arg1, arg2, arg3):
    assert instr.name[0:4] == 'SUBF'

    flags_update = []

    has_dot = False
    has_c = False
    has_e = False
    has_o = False

    for l in instr.name[4:]:
        if l == '.':
            has_dot = True
        elif l == 'C':
            has_c = True
        elif l == 'E':
            has_e = True
        elif l == 'O':
            has_o = True
        elif l == 'I' or l == 'M' or l == 'S' or l == 'Z':
            pass	# Taken care of earlier
        else:
            assert False

    if has_e:
        arg3 = arg3 + XER_CA.zeroExtend(32)
        arg2 = arg2 + ExprInt(1, 32)

    rvalue = arg3 - arg2

    over_expr = None
    if has_o:
        msb1 = arg2.msb()
        msb2 = arg3.msb()
        msba = rvalue.msb()
        over_expr = (msb1 ^ msb2) & (msb1 ^ msba)
        flags_update.append(ExprAff(XER_OV, over_expr))
        flags_update.append(ExprAff(XER_SO, XER_SO | over_expr))

    if has_dot:
        flags_update += mn_compute_flags(rvalue, over_expr)

    if has_c or has_e:
        carry_expr = ((((arg3 ^ arg2) ^ rvalue) ^
                       ((arg3 ^ rvalue) & (arg3 ^ arg2))).msb())
        flags_update.append(ExprAff(XER_CA, ~carry_expr))

    return ([ ExprAff(arg1, rvalue) ] + flags_update), []

def mn_do_xor(ir, instr, ra, rs, rb):
    rvalue = rs ^ rb
    ret = [ ExprAff(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_b(ir, instr, arg1, arg2 = None):
    if arg2 is not None:
        arg1 = arg2
    return [ ExprAff(PC, arg1), ExprAff(ir.IRDst, arg1) ], []

def mn_bl(ir, instr, arg1, arg2 = None):
    if arg2 is not None:
        arg1 = arg2
    return [ ExprAff(LR, ExprId(ir.get_next_instr(instr), 32)),
             ExprAff(PC, arg1),
             ExprAff(ir.IRDst, arg1) ], []

def mn_get_condition(instr):
    bit = instr.additional_info.bi & 0b11
    cr = instr.args[0].name
    return all_regs_ids_byname[cr + '_' + ['LT', 'GT', 'EQ', 'SO'][bit]]

def mn_do_cond_branch(ir, instr, dest):
    bo = instr.additional_info.bo
    bi = instr.additional_info.bi
    ret = []

    if bo & 0b00100:
        ctr_cond = True
    else:
        ret.append(ExprAff(CTR, CTR - ExprInt(1, 32)))
        ctr_cond = ExprCond(CTR ^ ExprInt(1, 32), ExprInt(1, 1), ExprInt(0, 1))
        if bo & 0b00010:
            ctr_cond = ~ctr_cond

    if (bo & 0b10000):
        cond_cond = True
    else:
        cond_cond = mn_get_condition(instr)
        if not (bo & 0b01000):
            cond_cond = ~cond_cond

    if ctr_cond != True or cond_cond != True:
        if ctr_cond != True:
            condition = ctr_cond
            if cond_cond != True:
                condition = condition & cond_cond
        else:
            condition = cond_cond
        dest_expr = ExprCond(condition, dest,
                             ExprId(ir.get_next_instr(instr), 32))
    else:
        dest_expr = dest

    if instr.name[-1] == 'L' or instr.name[-2:-1] == 'LA':
        ret.append(ExprAff(LR, ExprId(ir.get_next_instr(instr), 32)))

    ret.append(ExprAff(PC, dest_expr))
    ret.append(ExprAff(ir.IRDst, dest_expr))

    return ret, []

def mn_do_nop_warn(ir, instr, *args):
    print "Warning, instruction %s implemented as NOP" % instr
    return [], []

@sbuild.parse
def mn_cmp_signed(arg1, arg2, arg3):
    crf_dict[arg1]['LT'] = ((arg2 - arg3) ^
                            ((arg2 ^ arg3) & ((arg2 - arg3) ^ arg2))).msb()
    crf_dict[arg1]['GT'] = ((arg3 - arg2) ^
                            ((arg3 ^ arg2) & ((arg3 - arg2) ^ arg3))).msb()
    crf_dict[arg1]['EQ'] = i1(0) if arg2 - arg3 else i1(1)
    crf_dict[arg1]['SO'] = XER_SO

@sbuild.parse
def mn_cmp_unsigned(arg1, arg2, arg3):
    crf_dict[arg1]['LT'] = (((arg2 - arg3) ^
                             ((arg2 ^ arg3) & ((arg2 - arg3) ^ arg2))) ^
                            arg2 ^ arg3).msb()
    crf_dict[arg1]['GT'] = (((arg3 - arg2) ^
                             ((arg3 ^ arg2) & ((arg3 - arg2) ^ arg3))) ^
                            arg2 ^ arg3).msb()
    crf_dict[arg1]['EQ'] = i1(0) if arg2 - arg3 else i1(1)
    crf_dict[arg1]['SO'] = XER_SO

def mn_nop(ir, instr, *args):
    return [], []

@sbuild.parse
def mn_or(arg1, arg2, arg3):
    arg1 = arg2 | arg3

@sbuild.parse
def mn_assign(arg1, arg2):
    arg2 = arg1

def mn_stb(ir, instr, arg1, arg2):
    dest = ExprMem(arg2.arg, 8)
    return [ExprAff(dest, ExprSlice(arg1, 0, 8))], []

@sbuild.parse
def mn_stwu(arg1, arg2):
    arg2 = arg1
    arg1 = arg2.arg

sem_dir = {
    'B': mn_b,
    'BA': mn_b,
    'BL': mn_bl,
    'BLA': mn_bl,
    'CMPLW': mn_cmp_unsigned,
    'CMPLWI': mn_cmp_unsigned,
    'CMPW': mn_cmp_signed,
    'CMPWI': mn_cmp_signed,
    'CNTLZW': mn_do_cntlzw,
    'CNTLZW.': mn_do_cntlzw,
    'ECIWX': mn_do_nop_warn,
    'ECOWX': mn_do_nop_warn,
    'EIEIO': mn_do_nop_warn,
    'EQV': mn_do_eqv,
    'EQV.': mn_do_eqv,
    'ICBI': mn_do_nop_warn,
    'ISYNC': mn_do_nop_warn,
    'MCRF': mn_do_mcrf,
    'MCRXR': mn_do_mcrxr,
    'MFCR': mn_do_mfcr,
    'MFMSR': mn_mfmsr,
    'MFSPR': mn_mfspr,
    'MFSR': mn_do_nop_warn,
    'MFSRIN': mn_do_nop_warn,
    'MFTB': mn_mfmsr,
    'MTCRF': mn_mtcrf,
    'MTMSR': mn_mtmsr,
    'MTSPR': mn_mtspr,
    'MTSR': mn_do_nop_warn,
    'MTSRIN': mn_do_nop_warn,
    'NAND': mn_do_nand,
    'NAND.': mn_do_nand,
    'NOR': mn_do_nor,
    'NOR.': mn_do_nor,
    'RFI': mn_do_rfi,
    'SC': mn_do_nop_warn,
    'SLW': mn_do_slw,
    'SLW.': mn_do_slw,
    'SRAW': mn_do_sraw,
    'SRAW.': mn_do_sraw,
    'SRAWI': mn_do_srawi,
    'SRAWI.': mn_do_srawi,
    'SRW': mn_do_srw,
    'SRW.': mn_do_srw,
    'SYNC': mn_do_nop_warn,
    'TLBIA': mn_do_nop_warn,
    'TLBIE': mn_do_nop_warn,
    'TLBSYNC': mn_do_nop_warn,
    'TW': mn_do_nop_warn,
    'TWI': mn_do_nop_warn,
}


class ir_ppc32b(IntermediateRepresentation):

    def __init__(self, symbol_pool=None):
        super(ir_ppc32b, self).__init__(mn_ppc, 'b', symbol_pool)
        self.pc = mn_ppc.getpc()
        self.sp = mn_ppc.getsp()
        self.IRDst = expr.ExprId('IRDst', 32)
        self.addrsize = 32

    def get_ir(self, instr):
        args = instr.args[:]
        if instr.name[0:5] in [ 'ADDIS', 'ORIS', 'XORIS', 'ANDIS' ]:
            args[2] = ExprInt(args[2].arg << 16, 32)
        if instr.name[0:3] == 'ADD':
            if instr.name[0:4] == 'ADDZ':
                last_arg = ExprInt(0, 32)
            elif instr.name[0:4] == 'ADDM':
                last_arg = ExprInt(0xFFFFFFFF, 32)
            else:
                last_arg = args[2]
            instr_ir, extra_ir = mn_do_add(self, instr, args[0], args[1],
                                           last_arg)
        elif instr.name[0:3] == 'AND':
            instr_ir, extra_ir = mn_do_and(self, instr, *args)
        elif instr.additional_info.bo_bi_are_defined:
            name = instr.name
            if name[-1] == '+' or name[-1] == '-':
                name = name[0:-1]
            if name[-3:] == 'CTR' or name[-4:] == 'CTRL':
                arg1 = ExprCompose(ExprInt(0, 2), CTR[2:32])
            elif name[-2:] == 'LR' or name[-3:] == 'LRL':
                arg1 = ExprCompose(ExprInt(0, 2), LR[2:32])
            else:
                arg1 = args[1]
            instr_ir, extra_ir = mn_do_cond_branch(self, instr, arg1)
        elif instr.name[0:2] == 'CR':
            instr_ir, extra_ir = mn_do_cr(self, instr, *args)
        elif instr.name[0:3] == 'DCB':
            instr_ir, extra_ir = mn_do_nop_warn(self, instr, *args)
        elif instr.name[0:3] == 'DIV':
            instr_ir, extra_ir = mn_do_div(self, instr, *args)
        elif instr.name[0:4] == 'EXTS':
            instr_ir, extra_ir = mn_do_exts(self, instr, *args)
        elif instr.name[0] == 'L':
            instr_ir, extra_ir = mn_do_load(self, instr, *args)
        elif instr.name[0:3] == 'MUL':
            instr_ir, extra_ir = mn_do_mul(self, instr, *args)
        elif instr.name[0:3] == 'NEG':
            instr_ir, extra_ir = mn_do_neg(self, instr, *args)
        elif instr.name[0:2] == 'OR':
            instr_ir, extra_ir = mn_do_or(self, instr, *args)
        elif instr.name[0:2] == 'RL':
            instr_ir, extra_ir = mn_do_rotate(self, instr, args[0], args[1],
                                              args[2], args[3].arg.arg,
                                              args[4].arg.arg)
        elif instr.name == 'STMW':
            instr_ir, extra_ir = mn_do_stmw(self, instr, *args)
        elif instr.name[0:2] == 'ST':
            instr_ir, extra_ir = mn_do_store(self, instr, *args)
        elif instr.name[0:4] == 'SUBF':
            if instr.name[0:5] == 'SUBFZ':
                last_arg = ExprInt(0, 32)
            elif instr.name[0:5] == 'SUBFM':
                last_arg = ExprInt(0xFFFFFFFF, 32)
            else:
                last_arg = args[2]
            instr_ir, extra_ir = mn_do_sub(self, instr, args[0], args[1],
                                           last_arg)
        elif instr.name[0:3] == 'XOR':
            instr_ir, extra_ir = mn_do_xor(self, instr, *args)
        else:
            instr_ir, extra_ir = sem_dir[instr.name](self, instr, *args)

        return instr_ir, extra_ir

    def get_next_instr(self, instr):
        l = self.symbol_pool.getby_offset_create(instr.offset  + 4)
        return l

    def get_next_break_label(self, instr):
        l = self.symbol_pool.getby_offset_create(instr.offset  + 4)
        return l
