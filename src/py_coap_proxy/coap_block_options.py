from scapy.contrib.coap import coap_options

# Constants for CoAP Block Options
BLOCK1 = "Block1"
BLOCK2 = "Block2"

# Update the CoAP options dictionary with BLOCK1 and BLOCK2 options
coap_options[0].update({
    23: BLOCK2,
    27: BLOCK1
})

coap_options[1].update({
    BLOCK2: 23,
    BLOCK1: 27,
})


def get_coap_block_opt(options):
    """
    Retrieve the CoAP block option (Block1 or Block2)
    from the provided options.

    Args:
        options (list): A list of tuples representing CoAP options.

    Returns:
        tuple: The option tuple for Block1 or Block2 if found, otherwise None.
    """
    for opt_tuple in options:
        if opt_tuple[0] == BLOCK1:
            return opt_tuple
        elif opt_tuple[0] == BLOCK2:
            return opt_tuple
    return None


def set_coap_Block2_opt(options, new_block2_opt):
    """
    Set or replace the Block2 option in the provided CoAP options.

    Args:
        options (list): A list of tuples representing CoAP options.
        new_block2_opt (tuple): The new Block2 option to set.

    Returns:
        list: The updated list of CoAP options.

    Raises:
        ValueError: If no Block2 option is found in the provided options.
    """
    for i in range(len(options)):
        if options[i][0] == BLOCK2:
            options[i] = new_block2_opt
            return options
    raise ValueError("No Block2 option in the packet")


class CoAPBlockOption:
    """
    Represents a CoAP Block Option, extracting the relevant fields.

    Attributes:
        opt_name (str): The name of the option (Block1 or Block2).
        opt_value (int): The raw byte value of the option.
        num (int): The block number.
        m (int): The 'M' (more) flag.
        szx (int): The block size exponent.
    """

    def __init__(self, opt):
        """
        Initializes a CoAPBlockOption instance by parsing the given option.

        Args:
            opt (tuple): A tuple containing the option name and value.
        """
        self.opt_name = self.type_of_block = opt[0]
        self.opt_value = opt[1][0]
        self.num = (0xF0 & self.opt_value) >> 4
        self.m = (0x08 & self.opt_value) >> 3
        self.szx = 2 ** ((0x05 & self.opt_value) + 4)

    def get_block_opt(self):
        """
        Returns a string representation of the block option fields.

        Returns:
            str: A formatted string with the
            block option's NUM, M, and SZX values.
        """
        return f"NUM: {self.num}, M: {self.m}, SZX: {self.szx}"


def create_coap_block_option(type_of_block=BLOCK2, num=0, m=0, szx=0):
    """
    Creates a CoAP block option with the given parameters.

    Args:
        type_of_block (str): The type of block, either BLOCK1 or BLOCK2.
        num (int): The block number (must be 0-15).
        m (int): The 'M' (more) flag (must be 0 or 1).
        szx (int): The block size
        (must be one of 16, 32, 64, 128, 256, 512, 1024).

    Returns:
        tuple: A tuple representing the block option.

    Raises:
        ValueError: If the provided `num`, `m`, or `szx` is invalid.
    """
    # Validate the inputs
    if not (0 <= num <= 15):
        raise ValueError("NUM must be a 4-bit value (0-15)")
    if not (0 <= m <= 1):
        raise ValueError("M must be a 1-bit value (0 or 1)")

    # Block size lookup table
    szx_table = [16, 32, 64, 128, 256, 512, 1024]

    # Validate szx
    try:
        SZX = szx_table.index(szx)
    except ValueError:
        raise ValueError(
            f"SZX must be one of the following values: {szx_table}")

    # Combine fields into a single byte
    block_option = (num << 4) | (m << 3) | SZX

    # Return the appropriate block option tuple
    if type_of_block == BLOCK2:
        return (BLOCK2, block_option.to_bytes(1))
    else:
        return (BLOCK1, block_option.to_bytes(1))
