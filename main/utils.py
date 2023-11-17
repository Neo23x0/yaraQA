import binascii


def calculate_uint_replacement(value, value_type, position):
	"""
	Calculate a unit alternative for a 'string at position' expression 
	"""
	value_len = len(value)
	uint_string = "(couldn't transform)"
	# Transform position to int
	pos_int = 0
	if position.startswith("0x"):
		pos_int = int(position,16)
	else:
		try:
			pos_int = int(position)
		except Exception as e:
			return uint_string

	# Transform the values
	if value_len == 1:
		hex_string = binascii.hexlify(value.encode('utf-8')).decode('utf-8')
		uint_string = "uint8(%d) == 0x%s" % (pos_int, hex_string)
	elif value_len == 2:
		hex_string = binascii.hexlify(value.encode('utf-8')).decode('utf-8')
		uint_string = "uint16be(%d) == 0x%s" % (pos_int, hex_string)
	elif value_len == 3:
		hex_string = binascii.hexlify(value.encode('utf-8')).decode('utf-8')
		uint_string = "uint16be(%d) == 0x%s and uint8(%d) == 0x%s" % (pos_int, hex_string[:4], pos_int+2, hex_string[2:])
	elif value_len == 4:
		hex_string = binascii.hexlify(value.encode('utf-8')).decode('utf-8')
		uint_string = "uint16be(%d) == 0x%s and uint16be(%d) == 0x%s" % (pos_int, hex_string[:4], pos_int+2, hex_string[4:])
	return uint_string
