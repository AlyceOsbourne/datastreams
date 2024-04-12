import file_system
import blocks
import pickle

if __name__ == "__main__":
    import signers, processors
    
    block = blocks.HashedDataBlock()
    block["user.name"] = "Alyce"
    block["user.age"] = 32  
    block["user.city"] = "New York"
    block["user.zip"] = 10001
    block["user.address"] = "123 Main St"
    block["user.phone"] = 5551234567
    
    block["preferences.color"] = "blue"
    block["preferences.theme"] = "dark"
    block["preferences.font"] = "sans-serif"
    
    signer = signers.CompoundSigner(
            signers.HMACSigner.new(),
            signers.FingerprintSigner.new()
    )
    
    processor = processors.CompoundProcessor(
            processors.ZlibProcessor(),
            processors.FernetProcessor.new()
    )
    
    file = file_system.SignedFile(
            "test.txt",
            signer=signer,
            processor=processor
    )
    
    file.write(pickle.dumps(block))
    read_block = pickle.loads(file.read())
    print(read_block)