from file_system import SignedFile
from signers import HashSigner, RSASigner, FingerprintSigner, HMACSigner, ECDSASigner, CompoundSigner
from processors import ZlibProcessor, FernetProcessor, CompoundProcessor

def test_signed_file(data, signer, processor):
    file = SignedFile(
            "test.txt", 
            signer=signer,
            processor=processor
    )
    file.write(data)
    read_data = file.read()
    assert read_data == data, f"Expected {data!r}, but got {read_data!r}"
    with open(file.path, "wb") as f:
        f.write(data)
    try:
        file.read()
    except ValueError as e:
        pass
    else:
        raise AssertionError("Expected ValueError")
    file.delete()
    print(f"Passed test for {signer.__class__.__name__} and {processor.__class__.__name__}")
def run_tests():
    data = b"Hello, World!"
    for signer in [
            hs:= HashSigner("sha256"),
            rs:=RSASigner.new(), 
            fs:=FingerprintSigner.new(),
            hs:=HMACSigner.new(),
            es:=ECDSASigner.new(),
            CompoundSigner(
                hs,
                rs,
                fs,
                hs,
                es
            )
            
    ]:
        for processor in [
                zl:=ZlibProcessor(), 
                fp:=FernetProcessor.new(),
                CompoundProcessor(
                    zl,
                    fp
                )
        ]:
            test_signed_file(data, signer, processor)
    print("All tests passed!")
    
if __name__ == "__main__":
    run_tests()