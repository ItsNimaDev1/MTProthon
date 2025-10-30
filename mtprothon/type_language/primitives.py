from io import BytesIO
import struct

from .tlobject import TLObject


# Base class for MTProto 32-bit signed integers.
# MTProto uses little-endian encoding for all integer types, which means the least significant byte is stored first.
class Int(TLObject):
    LENGTH = 4

    def serialize(self, signed: bool = True) -> bytes:
        # Serializes the integer into a byte representation using little-endian.
        return self.value.to_bytes(self.LENGTH, byteorder="little", signed=signed)

    @classmethod
    def deserialize(cls, data: BytesIO, signed: bool = True) -> int:
        # Deserializes a byte representation back into an integer.
        return int.from_bytes(data.read(cls.LENGTH), byteorder="little", signed=signed)


# MTProto 64-bit integer type, extending the base Int class.
# Used for larger numerical values and timestamps.
class Long(Int):
    LENGTH = 8


# MTProto 128-bit integer type, commonly used for message identifiers and authentication.
class Int128(Int):
    LENGTH = 16


# MTProto 256-bit integer type, commonly used for cryptographic operations and keys.
class Int256(Int):
    LENGTH = 32


# MTProto double-precision floating point number (8 bytes).
# This class handles floating point values in MTProto serialization.
class Double(TLObject):
    def serialize(self):
        # Serializes the double value into 8 bytes using little-endian format.
        return struct.pack('<d', self.value)

    @classmethod
    def deserialize(cls, data: BytesIO):
        # Deserializes 8 bytes back into a double value.
        return struct.unpack('<d', data.read(8))[0]


# MTProto boolean type.
# Uses specific constructor IDs to represent true/false values within the MTProto framework.
class Bool(TLObject):
    # TL constructor IDs for boolean values
    BOOL_TRUE = 0x997275b5  # MTProto's representation of True
    BOOL_FALSE = 0xbc799737  # MTProto's representation of False

    def serialize(self) -> bytes:
        # Serializes the boolean value into its corresponding constructor ID.
        constructor_id = self.BOOL_TRUE if self.value else self.BOOL_FALSE
        return Int(constructor_id).serialize(signed=False)

    @classmethod
    def deserialize(cls, data: BytesIO) -> bool:
        # Deserializes the constructor ID back into a boolean value.
        return Int.deserialize(data, signed=False) == cls.BOOL_TRUE


# MTProto bytes serialization.
# Implements TL's bytes serialization scheme with padding to ensure data alignment.
class Bytes(TLObject):
    def serialize(self) -> bytes:
        length = len(self.value)

        # MTProto's compact format for byte strings:
        # If length <= 253 bytes: single byte length prefix
        # If length > 253: 0xFE followed by 3 length bytes
        if length <= 253:
            result = bytes([length]) + self.value
        else:
            result = b"\xfe" + length.to_bytes(length=3, byteorder="little") + self.value

        # Add padding to make total length divisible by 4, as per MTProto specification.
        current_length = len(result)
        padding_needed = (4 - (current_length % 4)) % 4
        result += b"\x00" * padding_needed
        return result

    @classmethod
    def deserialize(cls, data: BytesIO) -> bytes:
        # Read length prefix according to MTProto format.
        first_byte = int.from_bytes(data.read(1), byteorder="little")

        if first_byte <= 253:
            length = first_byte
        else:
            length = int.from_bytes(data.read(3), byteorder="little")

        return data.read(length)


# MTProto UTF-8 string type.
# Extends the Bytes type to handle UTF-8 encoding/decoding for string values.
class String(Bytes):
    def serialize(self) -> bytes:
        # Encodes the string to UTF-8 before serialization.
        self.value = self.value.encode("utf-8")
        return super().serialize()

    @classmethod
    def deserialize(cls, data: BytesIO) -> str:
        # Deserializes the byte data and decodes it from UTF-8 back to a string.
        # Uses 'replace' error handler to handle invalid UTF-8 sequences.
        return super().deserialize(data).decode(errors="replace")


# MTProto vector type (generic container).
# Used to serialize lists/arrays of TL objects, allowing for flexible data structures.
class Vector(TLObject):
    # TL constructor ID for vector type
    ID = 0x1CB5C415

    def serialize(self):
        # Vector format: constructor_id + count + [items]
        result = Int(self.ID).serialize()
        result += Int(len(self.value)).serialize()

        # Serialize each item in the vector
        for item in self.value:
            result += item.serialize()

        return result

    @classmethod
    def deserialize(cls, data: BytesIO, type):
        # Read vector constructor and item count
        constructor = Int.deserialize(data)
        count = Int.deserialize(data)

        # Deserialize each item in the vector according to its type
        items = []
        for _ in range(count):
            item = type.deserialize(data)
            items.append(item)

        return items
