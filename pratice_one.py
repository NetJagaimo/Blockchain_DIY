import time
import hashlib

class Transaction:
    def __init__(self, sender, receiver, amounts, message):
        self.sender = sender
        self.receiver = receiver
        self.amounts = amounts
        self.message = message


class Block:
    def __init__(self, previous_hash, difficulty, miner, miner_rewards):
        self.previous_hash = previous_hash
        self.hash = ''
        self.difficulty = difficulty
        self.nonce = 0
        self.timestamp = int(time.time())
        self.transactions = []
        self.miner = miner
        self.miner_rewards = miner_rewards


class BlockChain:
    def __init__(self):
        self.difficulty = 5
        self.block_limitation = 16
        self.chain = []
        self.pending_transactions = []
        self.miner_rewards = 10
    
    def transaction_to_string(self, transaction):
        transaction_dict = {
            'sender': str(transaction.sender),
            'receiver': str(transaction.receiver),
            'amounts': transaction.amounts,
            'message': transaction.message
        }

        return str(transaction_dict)
    
    def get_transactions_string(self, block):
        transaction_str = ''
        for transaction in block.transactions:
            transaction_str += self.transaction_to_string(transaction) 
        
        return transaction_str
    
    def get_hash(self, block, nonce):
        s = hashlib.sha1()
        s.update(
            (
                block.previous_hash
                + str(block.timestamp)
                + self.get_transactions_string(block)
                + str(nonce)
            ).encode("utf-8")
        )
        h = s.hexdigest()

        return h
    
    def create_genesis_block(self):
        print("Create genesis block...")
        new_block = Block("now is better than never. although never is often better than *right* now.", self.difficulty, 'ping', self.miner_rewards)
        new_block.hash = self.get_hash(new_block, 0)
        self.chain.append(new_block)

    def add_transaction_to_block(self, block):
        if len(self.pending_transactions) > self.block_limitation:
            transaction_accepted = self.pending_transactions[:self.block_limitation]
            self.pending_transactions = self.pending_transactions[self.block_limitation:]
        else:
            transaction_accepted = self.pending_transactions
            self.pending_transactions = []
        
        block.transactions = transaction_accepted

    def mine_block(self, miner):
        start = time.process_time()
        last_block = self.chain[-1]
        new_block = Block(last_block.hash, self.difficulty, miner, self.miner_rewards)
        
        self.add_transaction_to_block(new_block)
        new_block.hash = self.get_hash(new_block, new_block.nonce)

        while new_block.hash[0: self.difficulty] != '0' * self.difficulty:
            new_block.nonce += 1
            new_block.hash = self.get_hash(new_block, new_block.nonce)

        time_consumed = round(time.process_time() - start, 5)
        print(f"Hash found: {new_block.hash} @ difficulty {self.difficulty}, time cost: {time_consumed}s")
        self.chain.append(new_block)
    
    def get_balance(self, account):
        balance = 0
        for block in self.chain:
            # Check miner reward
            if block.miner == account:
                balance += block.miner_rewards
            for transaction in block.transactions:
                if transaction.sender == account:
                    balance -= transaction.amounts
                elif transaction.receiver == account:
                    balance += transaction.amounts
        
        return balance
    
    def verify_blockchain(self):
        previous_hash = ''
        for i, block in enumerate(self.chain):
            if self.get_hash(block, block.nonce) != block.hash:
                print("Error:Hash not matched!")
                return False
            elif previous_hash != block.previous_hash and i:
                print("Error:Hash not matched to previous_hash")
                return False
            previous_hash = block.hash
        print("Hash correct!")

        return True
    
    def initialize_transaction(self, sender, receiver, amount, message):
        if self.get_balance(sender) < amount:
            print("Balance not enough!")
            return False
        new_transaction = Transaction(sender, receiver, amount, message)
        
        return new_transaction

if __name__ == '__main__':
    block_chain = BlockChain()
    block_chain.create_genesis_block()

    while True:
        block_chain.mine_block('client_A')
        
        if block_chain.get_balance('client_A') >= 50:
            transaction = block_chain.initialize_transaction('client_A', 'client_B', 30, 'For the goods.')
            if transaction:
                block_chain.pending_transactions.append(transaction)

        print('========== transactions in blocks ==========')
        for i, block in enumerate(block_chain.chain):
            print(f'Block {i}:')
            for transaction in block.transactions:
                print(block_chain.transaction_to_string(transaction))

        print('========== balance of clients ==========')
        print('client_A:', block_chain.get_balance('client_A'))
        print('client_B:', block_chain.get_balance('client_B'))

        print('========== pending transactions waiting for miner to process ==========')
        for transaction in block_chain.pending_transactions:
            print(block_chain.transaction_to_string(transaction))
        print('\n')