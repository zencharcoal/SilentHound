#!/usr/bin/python3

import time, sys, socket, argparse, pickle, json
from colorama import Fore, Style
from os.path import exists
from ldap3 import Server, Connection, SAFE_SYNC, SUBTREE, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPInvalidDNSyntaxResult, LDAPSocketOpenError
from alive_progress import alive_bar

# Constants
NTLM = "NTLM"
SIMPLE = "SIMPLE"
ANONYMOUS = "ANONYMOUS"

# Global Functions
def banner():
    dashline = "-" * 75
    print(Fore.RED + r"""
   _____ _ _            _   _    _                       _ 
  / ____(_) |          | | | |  | |                     | |
 | (___  _| | ___ _ __ | |_| |__| | ___  _   _ _ __   __| |
  \___ \| | |/ _ \ '_ \| __|  __  |/ _ \| | | | '_ \ / _` |
  ____) | | |  __/ | | | |_| |  | | (_) | |_| | | | | (_| |
 |_____/|_|_|\___|_| |_|\__|_|  |_|\___/ \__,_|_| |_|\__,_|

    """ + Fore.WHITE + """author: Nick Swink aka c0rnbread

    company: Layer 8 Security <layer8security.com>
    """ + Style.RESET_ALL)
    print(dashline + '\n')

def get_user_principal_name(cn, cn_upn_dict_list):
    user_cn = None
    for user in cn_upn_dict_list:
        if cn == user['CN']:
            user_cn = user['UserPrincipalName']
            break
    return user_cn

def get_unix_time(t):
    t -= 116444736000000000
    t /= 10000000
    return t

def print_table(items, header):
    col_len = [max(len(str(row[i])) for row in items) for i in range(len(header))]
    col_len = [max(cl, len(h)) for cl, h in zip(col_len, header)]

    output_format = ' '.join(['{:<%d}' % width for width in col_len])
    print(output_format.format(*header))
    print('  '.join(['-' * length for length in col_len]))

    for row in items:
        print(output_format.format(*row))

class Pickler:
    def __init__(self, filename):
        self.__filename = filename

    def save_object(self, data):
        try:
            print(Fore.YELLOW + f"[*] Writing cached data to {self.__filename}..." + Style.RESET_ALL)
            with open(self.__filename, "wb") as f:
                pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as err:
            print(Fore.RED + f"[!] Error during pickling object: {err}" + Style.RESET_ALL)

    def load_object(self):
        if not exists(self.__filename):
            return None
        try:
            with open(self.__filename, "rb") as f:
                print(Fore.YELLOW + f"[*] Located LDAP cache '{self.__filename}'. Delete cache to run updated query..." + Style.RESET_ALL)
                return pickle.load(f)
        except Exception as err:
            print(Fore.RED + f"[!] Error during unpickling object: {err}" + Style.RESET_ALL)
            return None

class Hound:
    def __init__(self, namingcontexts):
        self.__namingcontexts = namingcontexts
        self.__usernames = []
        self.__domain_admins_upn = []
        self.__domain_admins_cn = []
        self.__computers = []
        self.__ip_dict_list = []
        self.__description_dict_list = []
        self.__ou_list = []
        self.__group_user_dict_list = []
        self.__cn_upn_dict_list = []
        self.__loot_list = []
        self.__kerberostable_users = []
        self.__key_words = ['Pass','pass','pwd','Pwd','key','userPassword', 'secret']
        self.__default_pwd_words = ["maxPwdAge","minPwdAge","minPwdLength","pwdProperties","pwdHistoryLength","badPwdCount","badPasswordTime","pwdLastSet"]
        self.__special_words = ['Remote','Admin','Service']

    def dump_ldap(self):
        try:
            s = Server(args.target, use_ssl=args.ssl, get_info='ALL')
            password = args.password
            if args.username == '' and args.password == '':
                method = ANONYMOUS
            elif '\\' not in args.username:
                method = SIMPLE
            else:
                method = NTLM
                password = args.hashes if args.hashes else args.password

            if args.hashes and method == SIMPLE:
                print(Fore.RED + f"[!] Cannot use Pass the Hash with SIMPLE AUTH. Exiting..." + Style.RESET_ALL)
                sys.exit()

            server = "LDAPS" if args.ssl else "LDAP"
            print(Fore.BLUE + f"[-] Connecting with {method} AUTH to {server} server {args.target}..." + Style.RESET_ALL)

            connect = Connection(s, user=args.username, password=password, client_strategy=SAFE_SYNC, auto_bind=True, authentication=method)

            search_flt = "(objectClass=*)" # specific search filters
            results = connect.extend.standard.paged_search(search_base=self.__namingcontexts, search_filter=search_flt, search_scope=SUBTREE, attributes=ALL_ATTRIBUTES, get_operational_attributes=True)

            total_results = []
            for item in results:
                total_results.append(item)
            return total_results

        except LDAPInvalidCredentialsResult:
            print(Fore.RED + f"[!] Error - Invalid Credentials '{args.username}:{args.password}'" + Style.RESET_ALL)
            sys.exit()
        except LDAPInvalidDNSyntaxResult as err:
            print(Fore.RED + f"[!] Error - Invalid Syntax: {err}" + Style.RESET_ALL)
            sys.exit()
        except LDAPSocketOpenError as err:
            print(Fore.RED + f"[!] Error - Couldn't reach LDAP server" + Style.RESET_ALL)
            sys.exit()
        except Exception as err:
            print(Fore.RED + f"[!] Error - Failure binding to LDAP server\n {(err)}" + Style.RESET_ALL)
            sys.exit()

    def resolve_ipv4(self, timeout):
        start_time = time.time()
        with alive_bar(len(self.__computers), dual_line=True, title=Fore.YELLOW + "[*] Resolving hostnames" + Style.RESET_ALL) as bar:
            for host in self.__computers:
                try:
                    addrinfo = socket.getaddrinfo(host, 80, family=socket.AF_INET)
                    ipv4 = addrinfo[1][4][0]
                    self.__ip_dict_list.append({"Name": host, "Address": ipv4})
                except (socket.gaierror, IndexError, OSError):
                    self.__ip_dict_list.append({"Name": host, "Address": ""})
                except KeyboardInterrupt:
                    sys.exit()

                if (time.time() - start_time) > timeout:
                    print(Fore.YELLOW + f"[*] Reverse DNS taking too long, skipping..." + Style.RESET_ALL)
                    current_index = self.__computers.index(host)
                    for host_left in self.__computers[current_index:]:
                        self.__ip_dict_list.append({"Name": host_left, "Address": ""})
                    break

                bar()

    def extract_all(self, dump):
        def create_cn_upn_dict_list(dump):
            for row in dump:
                try:
                    if b'person' in row['raw_attributes']['objectClass']:
                        upn_blist = row['raw_attributes']["userPrincipalName"]
                        upn = upn_blist[0].decode('UTF-8')
                        cn_upn_dict = {"CN": row['dn'], "UserPrincipalName": upn}
                        self.__cn_upn_dict_list.append(cn_upn_dict)
                except KeyError:
                    pass

        create_cn_upn_dict_list(dump)

        for row in dump:
            try:
                if b'person' in row['raw_attributes']['objectClass'] and b'computer' not in row['raw_attributes']['objectClass']:
                    user_principal_name_blist = row['raw_attributes'].get('userPrincipalName')
                    if user_principal_name_blist:
                        user_principal_name = user_principal_name_blist[0].decode('UTF-8')
                        self.__usernames.append(user_principal_name)
                    else:
                        user_name_blist = row['raw_attributes'].get('sAMAccountName')
                        user_name = user_name_blist[0].decode('UTF-8')
                        self.__usernames.append(user_name)
            except KeyError:
                pass

            try:
                if b'group' in row['raw_attributes']['objectClass'] and b'Domain Admins' in row['raw_attributes']['cn']:
                    member_blist = row['raw_attributes']['member']
                    self.__domain_admins_cn = [member.decode('UTF-8') for member in member_blist]
                    for user_cn in self.__domain_admins_cn:
                        user_upn = get_user_principal_name(user_cn, self.__cn_upn_dict_list)
                        if user_upn:
                            self.__domain_admins_upn.append(user_upn)
                        else:
                            self.__domain_admins_upn.append(user_cn)
            except KeyError:
                pass

            try:
                if b'computer' in row['raw_attributes']['objectClass']:
                    cn_blist = row['raw_attributes']["cn"]
                    cn = cn_blist[0].decode('UTF-8')
                    if cn not in self.__computers:
                        self.__computers.append(cn)
            except KeyError:
                pass

            try:
                if b'person' in row['raw_attributes']['objectClass']:
                    upn_blist = row['raw_attributes']['userPrincipalName']
                    d_blist = row['raw_attributes']['description']
                    upn = upn_blist[0].decode('UTF-8')
                    d = d_blist[0].decode('UTF-8')
                    self.__description_dict_list.append({"UserPrincipalName": upn, "description": d})
            except KeyError:
                pass

            if args.groups:
                try:
                    if b'group' in row['raw_attributes']['objectClass']:
                        member_blist = row['raw_attributes']['member']
                        member_list = [i.decode('UTF-8') for i in member_blist]
                        self.__group_user_dict_list.append({'Group': row['dn'], 'Members': member_list})
                except KeyError:
                    pass

            if args.org_unit:
                try:
                    if b'organizationalUnit' in row['raw_attributes']['objectClass']:
                        self.__ou_list.append(row['dn'])
                except KeyError:
                    pass

            if args.keywords:
                try:
                    for key in row['raw_attributes']:
                        object_name = row['dn']
                        if any(word in key for word in self.__key_words):
                            if key not in self.__default_pwd_words:
                                self.__loot_list.append(f"({object_name}) {key}={(row['raw_attributes'].get(key))[0].decode('UTF-8')}")
                        for item in row['raw_attributes'].get(key):
                            try:
                                item = item.decode('UTF-8')
                                if any(word in item for word in self.__key_words):
                                    self.__loot_list.append(item)
                            except (UnicodeDecodeError, AttributeError):
                                continue
                except KeyError:
                    continue

    def kerberoastable(self, total_results):
        if args.kerberoast:
            import datetime
            kerberoastable = []

            for obj in total_results:
                try:
                    servicePrincipalName = obj['raw_attributes']['servicePrincipalName']
                    if b'computer' not in obj['raw_attributes']['objectClass'] and servicePrincipalName:
                        kerberoastable.append(obj)
                except KeyError:
                    continue

            for obj in kerberoastable:
                try:
                    sAMAccountName = obj['raw_attributes'].get('sAMAccountName', [''])[0].decode('UTF-8')
                    userAccountControl = int(obj['raw_attributes'].get('userAccountControl', ['0'])[0].decode('UTF-8'))
                    memberOf = obj['raw_attributes'].get('memberOf', [''])[0].decode('UTF-8')
                    pwdLastSet = get_unix_time(int(obj['raw_attributes'].get('pwdLastSet', ['0'])[0].decode('UTF-8')))
                    pwdLastSet = 'never' if pwdLastSet == 0 else str(datetime.date.fromtimestamp(pwdLastSet))
                    lastLogon = get_unix_time(int(obj['raw_attributes'].get('lastLogon', ['0'])[0].decode('UTF-8')))
                    lastLogon = 'never' if lastLogon == 0 else str(datetime.date.fromtimestamp(lastLogon))
                    SPNs = [spn.decode('UTF-8') for spn in obj['raw_attributes'].get('servicePrincipalName', [])]

                    disabled_UACs = [514, 546, 66050, 66082, 262658, 262690, 328194, 328226]
                    if userAccountControl not in disabled_UACs:
                        for spn in SPNs:
                            self.__kerberostable_users.append([spn, sAMAccountName, memberOf, pwdLastSet, lastLogon])
                except (KeyError, ValueError):
                    continue

    def print(self):
        def print_list(title, data):
            print(Fore.GREEN + f"[+] {title} [{len(data)}]" + Style.RESET_ALL)
            for item in data:
                print(item)
            print('\n')

        print_list("Hosts", [f"{host['Name']} {host['Address']}" for host in self.__ip_dict_list])
        print_list("Domain Admins", self.__domain_admins_upn)
        print_list("Domain Users", self.__usernames)
        print_list("Descriptions", [f"{desc['UserPrincipalName']} - {desc['description']}" for desc in self.__description_dict_list])

        if args.groups:
            print_list("Group Memberships", [f"{group['Group']} Members: {group['Members']}" for group in self.__group_user_dict_list])

        if args.org_unit:
            print_list("Organizational Units", self.__ou_list)

        if args.keywords:
            print_list("Key Strings", self.__loot_list)

        if args.kerberoast:
            print(Fore.GREEN + f"[+] Kerberoastable Users [{len(self.__kerberostable_users)}]" + Style.RESET_ALL)
            if self.__kerberostable_users:
                print_table(self.__kerberostable_users, header=["ServicePrincipalName", "Name", "MemberOf", "PasswordLastSet", "LastLogon"])
                print('\n')

    def save_json(self, filename, data):
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

    def outfiles(self):
        if args.output:
            output_prefix = args.output
            self.save_json(f"{output_prefix}-users.json", self.__usernames)
            self.save_json(f"{output_prefix}-domain_admins.json", self.__domain_admins_upn)
            self.save_json(f"{output_prefix}-hosts.json", self.__ip_dict_list)
            self.save_json(f"{output_prefix}-descriptions.json", self.__description_dict_list)
            if args.groups:
                self.save_json(f"{output_prefix}-groups.json", self.__group_user_dict_list)
            if args.org_unit:
                self.save_json(f"{output_prefix}-org.json", self.__ou_list)
            if args.keywords:
                self.save_json(f"{output_prefix}-keywords.json", self.__loot_list)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Quietly enumerate an Active Directory environment.')
    parser.add_argument('target', metavar='TARGET', type=str, help='Domain Controller IP')
    parser.add_argument('domain', type=str, help="Dot (.) separated Domain name including both contexts e.g. ACME.com | HOME.local | htb.net")
    parser.add_argument('-u', '--username', default='', type=str, help="Supports SIMPLE & NTLM BIND. SIMPLE BIND use username e.g. bobdole | NTLM BIND use domain\\\\user e.g. HOME.local\\\\bobdole")
    parser.add_argument('-p', '--password', default='', type=str, help="LDAP or Active Directory password")
    parser.add_argument('--hashes', type=str, help="Uses NTLM BIND to authenticate with NT:LM hashes")
    parser.add_argument('-o', '--output', type=str, help="Name for output files. Creates output files for hosts, users, domain admins, and descriptions in the current working directory.")
    parser.add_argument('-g', '--groups', action='store_true', help="Display Group names with user members.")
    parser.add_argument('-n', '--org-unit', action='store_true', help="Display Organizational Units.")
    parser.add_argument('-k', '--keywords', action='store_true', help="Search for a list of key words in LDAP objects.")
    parser.add_argument('--kerberoast', action='store_true', help="Identify kerberoastable user accounts by their SPNs.")
    parser.add_argument('--ssl', action='store_true', help="Use a secure LDAP server on default 636 port.")
    parser.add_argument('--dns-timeout', type=int, default=90, help="Timeout for resolving hostnames (seconds). e.g. --dns-timeout 90")
    args = parser.parse_args()

    if '.' not in args.domain:
        print("[!] Domain must contain DOT (.); e.g. 'ACME.com'")
        sys.exit()
    else:
        domain = args.domain.split('.')[0]
        ext = args.domain.split('.')[1]

        l = args.domain.split('.')
        namingcontexts = ",".join([f"DC={word}" for word in l])

    print()
    banner()

    h1 = Hound(namingcontexts)
    p1 = Pickler(f".{domain}-{ext}.pickle")
    cache = p1.load_object()

    if not cache:
        dump = h1.dump_ldap()
        p1.save_object(dump)
    else:
        dump = cache

    time.sleep(1.5)

    h1.extract_all(dump)
    h1.resolve_ipv4(args.dns_timeout)
    h1.kerberoastable(dump)
    h1.print()
    h1.outfiles()
