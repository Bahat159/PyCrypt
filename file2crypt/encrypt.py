from encryptLibrary import read_with_file


myFile = input("Enter data to encrypt => ")
encrypted_data = read_with_file(myFile)
print(encrypted_data)
