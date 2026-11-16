#!/usr/bin/env python3
# Minimal DEX reader to TRACE a specific method's bytecode: resolves string/
# type/method ids and decodes the invoke-* / const-string / if-* / return-*
# opcodes needed to follow a Binder asInterface path. Not a full disassembler.
import struct, sys

class Dex:
    def __init__(self, data):
        self.d = data
        hdr = data
        self.string_ids_off = struct.unpack_from('<I', hdr, 0x3c)[0]
        self.string_ids_size = struct.unpack_from('<I', hdr, 0x38)[0]
        self.type_ids_off = struct.unpack_from('<I', hdr, 0x44)[0]
        self.type_ids_size = struct.unpack_from('<I', hdr, 0x40)[0]
        self.proto_ids_off = struct.unpack_from('<I', hdr, 0x4c)[0]
        self.proto_ids_size = struct.unpack_from('<I', hdr, 0x48)[0]
        self.field_ids_off = struct.unpack_from('<I', hdr, 0x54)[0]
        self.field_ids_size = struct.unpack_from('<I', hdr, 0x50)[0]
        self.method_ids_off = struct.unpack_from('<I', hdr, 0x5c)[0]
        self.method_ids_size = struct.unpack_from('<I', hdr, 0x58)[0]
        self.class_defs_off = struct.unpack_from('<I', hdr, 0x64)[0]
        self.class_defs_size = struct.unpack_from('<I', hdr, 0x60)[0]

    def uleb(self, off):
        r=0; s=0
        while True:
            b=self.d[off]; off+=1; r|=(b&0x7f)<<s
            if not (b&0x80): break
            s+=7
        return r, off
    def string(self, idx):
        off = struct.unpack_from('<I', self.d, self.string_ids_off+idx*4)[0]
        _, off = self.uleb(off)
        end = self.d.index(0, off)
        return self.d[off:end].decode('utf-8','replace')
    def type_str(self, idx):
        sidx = struct.unpack_from('<I', self.d, self.type_ids_off+idx*4)[0]
        return self.string(sidx)
    def method(self, idx):
        cls, proto, name = struct.unpack_from('<HHI', self.d, self.method_ids_off+idx*8)
        return self.type_str(cls), self.string(name)
    def field(self, idx):
        cls, typ, name = struct.unpack_from('<HHI', self.d, self.field_ids_off+idx*8)
        return self.type_str(cls), self.type_str(typ), self.string(name)

    def iter_classes(self):
        for i in range(self.class_defs_size):
            base = self.class_defs_off + i*32
            cls_idx, _, _, _, _, _, data_off, _ = struct.unpack_from('<IIIIIIII', self.d, base)
            yield self.type_str(cls_idx), data_off

    def class_methods(self, data_off):
        if data_off==0: return []
        off=data_off
        sf,off=self.uleb(off); inf,off=self.uleb(off); dm,off=self.uleb(off); vm,off=self.uleb(off)
        # skip fields
        for _ in range(sf):
            _,off=self.uleb(off); _,off=self.uleb(off)
        for _ in range(inf):
            _,off=self.uleb(off); _,off=self.uleb(off)
        out=[]
        for grp,cnt in (('direct',dm),('virtual',vm)):
            midx=0
            for _ in range(cnt):
                di,off=self.uleb(off); _,off=self.uleb(off); code_off,off=self.uleb(off)
                midx+=di
                out.append((midx, code_off, grp))
        return out

    def decode(self, code_off):
        if code_off==0: return None
        regs, ins, outs, tries, dbg, insns_size = struct.unpack_from('<HHHHII', self.d, code_off)
        base = code_off+16
        units = struct.unpack_from('<%dH'%insns_size, self.d, base)
        return regs, ins, outs, units

OPLEN = {0x00:1,0x0e:1,0x0a:1,0x0b:1,0x0c:1,0x0d:1,0x12:1,0x1c:2,0x1a:2,0x1f:2,0x22:2,
         0x38:2,0x39:2,0x3b:2,0x6e:3,0x6f:3,0x70:3,0x71:3,0x72:3,0x54:2,0x55:3,0x5b:2,
         0x52:2,0x59:2,0x0f:1,0x10:1,0x11:1,0x21:1,0x20:2,0x23:2,0x62:2}
def op_len(units, i):
    op = units[i]&0xff
    if op==0x00 and units[i]>>8 in (1,2,3): # packed/sparse/fill payloads: bail
        return 1
    # default lengths by format; fall back to common sizes
    fixed = {0x6e:3,0x6f:3,0x70:3,0x71:3,0x72:3,0x74:3,0x75:3,0x76:3,
             0x1a:2,0x1c:2,0x1f:2,0x20:2,0x22:2,0x23:2,0x52:2,0x53:2,0x54:2,0x55:3,
             0x59:2,0x5b:2,0x62:2,0x38:2,0x39:2,0x3b:2,0x6c:2,0x6d:2}
    if op in fixed: return fixed[op]
    hi = {0x10:1,0x11:1,0x0e:1,0x0f:1,0x12:1,0x0a:1,0x0b:1,0x0c:1,0x0d:1,0x01:1,0x07:1,0x1d:1,0x1e:1,0x28:1,0x29:2,0x2a:3,0x21:1}
    return hi.get(op,1) if op not in hi else hi[op]

def dump_method(dex, cls, mname):
    for cname, doff in dex.iter_classes():
        if cname!=cls: continue
        for midx, code_off, grp in dex.class_methods(doff):
            c,n = dex.method(midx)
            if c==cls and n==mname and code_off:
                dec = dex.decode(code_off)
                if not dec: continue
                regs,ins,outs,units = dec
                print(f"# {cls}->{mname}  regs={regs} ins={ins} outs={outs} grp={grp}")
                i=0
                while i < len(units):
                    op = units[i]&0xff
                    txt=f"  {i:04x}: {op:02x}"
                    if op in (0x6e,0x6f,0x70,0x71,0x72):  # invoke-kind
                        ref=units[i+1]; tc,tn=dex.method(ref)
                        txt+=f" invoke {tc}->{tn}"
                    elif op==0x1a:  # const-string
                        txt+=f" const-string \"{dex.string(units[i+1])}\""
                    elif op==0x1c:  # const-class
                        txt+=f" const-class {dex.type_str(units[i+1])}"
                    elif op==0x1f:  # check-cast
                        txt+=f" check-cast {dex.type_str(units[i+1])}"
                    elif op==0x20:  # instance-of
                        txt+=f" instance-of {dex.type_str(units[i+1])}"
                    elif op in (0x52,0x53,0x54,0x55,0x58,0x59,0x5a,0x5b,0x5c): # iget/iput/sget/sput
                        try:
                            fc,ft,fn=dex.field(units[i+1]); txt+=f" field {fc}->{fn}:{ft}"
                        except: pass
                    elif op in (0x38,0x39):  # if-eqz/nez
                        txt+=f" if-z -> +{struct.unpack('<h',struct.pack('<H',units[i+1]))[0]}"
                    elif op in (0x0e,0x0f,0x10,0x11):  # returns
                        txt+=" return"
                    print(txt)
                    i += max(1, op_len(units,i))
                return True
    return False

if __name__=='__main__':
    path, cls, mname = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(path,'rb') as f: data=f.read()
    dex=Dex(data)
    if not dump_method(dex, cls, mname):
        print("NOT FOUND in", path)
