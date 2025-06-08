from .constants import BLOCK1, BLOCK2

class CoAPBlockOption():
    def __init__(self, opt):
        try:
            self.opt_name = self.type_of_block       = opt[0]
            self.opt_value                           = int.from_bytes(opt[1], "big")
            self.num                                 = (0xF0 & self.opt_value) >> 4;
            self.m                                   = (0x08 & self.opt_value) >> 3;
            self.szx                                 = 2**((0x05 & self.opt_value) + 4);
        except:
            self.num                                 = None
            self.m                                   = None
            self.szx                                 = None


    def get_block_opt(self):
        return f"NUM: {self.num}, M: {self.m}, SZX: {self.szx}"

def create_coap_block_option(type_of_block=BLOCK2, num=0, m=0, szx=0):
    if not (0 <= num <= 15):
        raise ValueError("NUM must be a 4-bit value (0-15)")
    if not (0 <= m <= 1):
        raise ValueError("M must be a 1-bit value (0 or 1)")
    szx_table = [16, 32, 64, 128, 256, 512, 1024]
    try:
        SZX = szx_table.index(szx)
    except ValueError:
        raise ValueError(f"szx must be set to one of this value {szx_table}")
    block_option = (num << 4) | (m << 3) | SZX
    if(type_of_block == BLOCK2):
        return (BLOCK2, block_option.to_bytes(1))
    else:
        return (BLOCK1, block_option.to_bytes(1))
