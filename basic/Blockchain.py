import datetime, logging, json
from hashlib import sha256

logging.basicConfig(format='[%(asctime)s][%(levelname)s] %(message)s', datefmt='%H:%M:%S', level=logging.INFO)
logging.info('Logging started')


def unixtime():
    return datetime.datetime.utcnow().timestamp()


def calculate_hash(index, previous_hash, timestamp, data):
    bstring = json.dumps([index, previous_hash, timestamp, data]).encode()
    sha256_hash = sha256(bstring).hexdigest()
    logging.debug('calculate_hash(%s, %s, %s, %s) => sha256(%s) => %s', index, previous_hash, timestamp, data, bstring,
                  sha256_hash)
    return sha256_hash


class Block:
    def __init__(self, index, previous_hash, timestamp, data):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = calculate_hash(index, previous_hash, timestamp, data)


class Chain:
    def __init__(self, genesis_block):
        self.chain = []
        self.chain.append(genesis_block)

    def add_block(self, block):
        if self.valid_block_relation(self.get_latest_block(), block):
            self.chain.append(block)
            logging.debug('Block #%s added with hash %s', block.index, block.hash)
        else:
            logging.error('Integrity failure when trying to add block with data %s', block.data)

    def get_latest_block(self):
        return self.chain[-1]

    def generate_new_block(self, block_data):
        previous_block = self.get_latest_block()
        return Block(previous_block.index + 1, previous_block.hash, unixtime(), block_data)

    def valid_block_relation(self, former_block, latter_block):
        # Index check
        if (latter_block.index - 1) != former_block.index:
            logging.error(
                'Index check failed when checking block relation (something is wrong with this index order: #%s => #%s)',
                former_block.index, latter_block.index)
            return False

        # Relation hash check
        if latter_block.previous_hash != former_block.hash:
            logging.error('Relation hash check failed when checking block relation (%s is not %s)',
                          latter_block.previous_hash, former_block.hash)
            return False

        # Hash integrity check
        for block in [former_block, latter_block]:
            new_hash = calculate_hash(block.index, block.previous_hash, block.timestamp, block.data)
            if new_hash != block.hash:
                logging.error(
                    'Hash integrity check failed when checking block relation. Block #%s hash should be %s but is in fact %s',
                    block.index, block.hash, new_hash)
                logging.debug('Offending block: [%s, %s, %s, %s]')
                return False

        return True

    def valid_block_chain(self, from_index=0):
        if from_index > (len(self.chain) - 2):
            if from_index > (len(self.chain) - 1):
                # Index out of bounds
                return False
            else:
                # Only one block to check
                block = self.chain[from_index]
                return calculate_hash(block.index, block.previous_hash, block.timestamp, block.data) == block.hash

        if from_index == 0:
            # We can skip ahead if 0 is selected, integrity is checked anyway when it is former_block
            from_index = 1

        for latter_block in self.chain[from_index:]:
            former_block = self.chain[latter_block.index - 1]
            logging.debug('Checking block relation between #%s and #%s', former_block.index, latter_block.index)
            if not self.valid_block_relation(former_block, latter_block):
                logging.error(
                    'Integrity failure when checking block with index #%s, the chain is invalid from this index',
                    latter_block.index)
                return False

        return True


if __name__ == '__main__':
    genesis_block = Block(0, None, unixtime(), 'The first block in this chain!')
    blockchain = Chain(genesis_block)
    logging.info('Blockchain initiated with genesis block')
    logging.debug('Initiated blockchain, genesis = [%s, %s, %s, %s] [%s]', genesis_block.index, genesis_block.previous_hash,
                  genesis_block.timestamp, genesis_block.data, genesis_block.hash)

    for i in range(1, 10):
        new_block = blockchain.generate_new_block('Block number {}'.format(i))
        # logging.info('Add: {prev} => {hash}'.format(prev=new_block.previous_hash, hash=new_block.hash))
        blockchain.add_block(new_block)

    logging.info('Blocks have been added, now %s blocks on blockchain', len(blockchain.chain))
    logging.info('Checking integrity..')
    if blockchain.valid_block_chain():
        logging.info('Integrity is ok!')

    import random, uuid

    random_block = random.choice(blockchain.chain)
    logging.info('Corrupting data for random block #%s', random_block.index)
    random_block.data = str(uuid.uuid4())
    logging.info('Checking integrity..')
    if blockchain.valid_block_chain():
        logging.info('Integrity is ok!')
