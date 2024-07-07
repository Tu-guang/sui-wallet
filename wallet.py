from bip_utils import Bip39SeedGenerator, Bip44Coins, Bip44
from bech32 import bech32_encode, convertbits
from mnemonic import Mnemonic


# only support ed25519 schema
class Suiwallet:

    def __init__(self, mnemonic: str, password='') -> None:
        self.mnemonic: str = mnemonic.strip()
        self.password = password
        self.pk_prefix = 'suiprivkey'
        self.ed25519_schema = '00'

    def get_address_pk(self, pk_with_prefix=True):
        seed_bytes = Bip39SeedGenerator(self.mnemonic).Generate(self.password)
        bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.SUI).DeriveDefaultPath()
        address = bip44_mst_ctx.PublicKey().ToAddress()
        pk = bip44_mst_ctx.PrivateKey().Raw().ToHex()  # hex type pk

        if pk_with_prefix:
            pk_bytes_with_schema = bytes.fromhex(f'{self.ed25519_schema}{pk}')
            pk_bit_arr = convertbits(pk_bytes_with_schema, 8, 5)
            pk = bech32_encode(self.pk_prefix, pk_bit_arr)  # result like "suiprivkey1q............"

        return address, pk


if __name__ == '__main__':
    for i in range(10):
        m = Mnemonic(language='english')
        mnc = m.generate()
        sw = Suiwallet(mnc)
        add, pk = sw.get_address_pk()
        print(f'mnemonic: {mnc}')
        print(f'address: {add}')
        print(f'pk: {pk}')
        with open("wallet.txt", 'a', encoding='utf-8') as f:
            f.write(f'{add},{pk},{mnc}\n')
