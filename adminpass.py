import hashlib
import getpass

def hash_password(password):
    """
    Hash a password using SHA-256 algorithm.
    
    Args:
        password (str): The plain text password to hash.
        
    Returns:
        str: The hashed password as a hexadecimal string.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    try:
        password = getpass.getpass("Enter password: ")
        verify_password = getpass.getpass("Verify password: ")
        
        if password != verify_password:
            print("Error: Passwords do not match!")
            return
        
        if not password:
            print("Error: Password cannot be empty!")
            return
            
        hashed = hash_password(password)
        print(f"\nSHA256 Hash: {hashed}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")

if __name__ == "__main__":
    main()