import requests
import hashlib
import sys
import PyPDF2

def request_api_data(hash_chars):
    url = "https://api.pwnedpasswords.com/range/" + hash_chars
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the api and try again")
    return res

def get_password_leaks_counts(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    # print(hashes)
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first_5_chars, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first_5_chars)
    # print(response)
    return get_password_leaks_counts(response, tail)


def main(filename):
    print()
    file = open(filename)

    # going line by line in the passwords txt file
    for password in file:

        # if the password contains a newline char then remove it
        # adjust hidden_password accordingly
        if password.find("\n") != -1:
            password = password[:len(password)-1]
            hidden_password = "*" * len(password)
        else:
            hidden_password = "*" * len(password)

        # num of password leaks for this password
        num_password_leaks = pwned_api_check(password)

        # returning message depending on severity of leaks (if any)
        if num_password_leaks:
            count = int(num_password_leaks)
            if count >= 100000:
                print(f"Password \"{hidden_password}\" was leaked {num_password_leaks} times!!!"
                      f"\n    RESET EVERYTHING & HOPE FOR THE BEST!!!\n")
            elif count >= 10000:
                print(f"Password \"{hidden_password}\" was leaked {num_password_leaks} times!"
                      f"\n    Change your password RN!\n")
            else:
                print(f"Password \"{hidden_password}\" was leaked {num_password_leaks} times!"
                      f"\n    Maybe change your password!\n")
        else:
            print(f"Password \"{hidden_password}\" was not leaked!"
                  f"\n    GOOD JOB!\n")

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))