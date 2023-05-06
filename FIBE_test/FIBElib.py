# 我要寫一個函式庫，我希望達成的目標是可以用PRE完成CP-ABE的重加密，但是我是要用CP-ABE來達成FIBE加密檔案的效果，每個擁有檔案F存取權的DU都有一個ID，例如Alice的ID"Alice"，ID可以用來
# 我想基於以下的函式庫來修改，以下函式庫功能上與我的類似，是使用CP-ABE加密檔案，並使用TBPRE重加密檔案，來加上時間的限制，但是我要修改成使用FIBE(簡化CP-ABE使用ID當作Attribute加密檔案，並且Access control都使用OR)加密檔案，並使用PRE重加密檔案，來新增新使用者的存取權，在Attributes中再OR新使用者的ID
# 我想要修改的函式庫是:abenc_tbpre_lww14.py，我想要修改的部分是:setup、registerUser、hashDate、encrypt、decrypt、reencrypt
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil

from functools import reduce
def setup(self, attributes):
    '''Global Setup (executed by CA)'''
    P0 = self.group.random(G1)  # generator
    P1 = self.group.random(G1)  # random element
    s = self.group.random()     # random number
    mk0 = self.group.random()   # random number
    mk1 = self.group.random()   # random number
    Q0 = P0 ** mk0            # Q0 = P0^mk0
    SK1 = P1 ** mk0          # SK1 = P1^mk0

    Htemp = lambda x, y: self.group.hash(x + y, ZR)
    H = {
        'user': lambda x: self.group.hash(str(x), ZR), # first convert G1 to str, then hash
        'attr': lambda x: Htemp(x,"_attribute"),    # Htemp is a function
        'sy': lambda x: Htemp(x,"_year"),        # Htemp is a function
        'sym': lambda x: Htemp(x,"_year_month"),    # Htemp is a function
        'symd': lambda x: Htemp(x,"_year_month_day")    # Htemp is a function
    }

    PK = { 'A': {}, 'Q0': Q0, 'P0': P0, 'P1': P1 }  # PK is a dictionary
    MK = { 'A': {}, 'mk0': mk0, 'mk1': mk1, 'SK1': SK1 }    # MK is a dictionary
    for attribute in attributes:    # attributes is a list
        ska = self.group.random()   # ska is a random number
        PK['A'][attribute] = P0 ** ska  # PK['A'][attribute] = P0^ska
        MK['A'][attribute] = ska        # MK['A'][attribute] = ska
    return (PK, MK, H)

def registerUser(self, PK, MK, H, user, attributes):
    '''Register a user with the CA'''
    ska = self.group.random()
    PK['A'][user] = PK['P0'] ** ska
    MK['A'][user] = ska
    for attribute in attributes:
        ska = self.group.random()
        PK['A'][attribute] = PK['P0'] ** ska
        MK['A'][attribute] = ska
    return (PK, MK)

def hashDate(self, H, date):
    '''Hash a date to a point on the curve'''
    return H['symd'](date)    # H['symd'] is a function

def encrypt(self, PK, H, M, date, attributes):
    '''Encrypt a message for a set of attributes'''
    s = self.group.random()
    C0 = PK['P1'] ** s  # C0 = P1^s
    C1 = M * (PK['Q0'] ** s) # C1 = M * Q0^s  (M is a point on the curve)
    C2 = {}   # C2 is a dictionary
    for attribute in attributes:
        r = self.group.random()   # r is a random number
        C2[attribute] = PK['A'][attribute] ** r   # C2[attribute] = A[attribute]^r
        C1 *= (PK['P0'] ** r)   # C1 = C1 * P0^r  (P0 is a point on the curve)
    C3 = self.hashDate(H, date) ** s   # C3 = H(date)^s   (H(date) is a point on the curve)
    return { 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3 }

def decrypt(self, PK, MK, H, CT, date, user):
    '''Decrypt a message for a user'''
    C0 = CT['C0']  # C0 is a point on the curve
    C1 = CT['C1']  # C1 is a point on the curve 
    C2 = CT['C2']  # C2 is a dictionary
    C3 = CT['C3']  # C3 is a point on the curve
    SK1 = MK['SK1']  # SK1 is a point on the curve
    SK2 = MK['A'][user]  # SK2 is a point on the curve
    SK = SK1 * SK2  # SK is a point on the curve
    return C1 * (pair(C0, SK) / pair(C3, PK['P1']))  # return M = C1 * (e(C0, SK) / e(C3, P1))

def reencrypt(self, PK, MK, H, CT, date, user, attributes):
    '''Re-encrypt a message for a set of attributes'''
    C0 = CT['C0']  # C0 is a point on the curve
    C1 = CT['C1']  # C1 is a point on the curve
    C2 = CT['C2']  # C2 is a dictionary
    C3 = CT['C3']  # C3 is a point on the curve
    SK1 = MK['SK1']  # SK1 is a point on the curve
    SK2 = MK['A'][user]  # SK2 is a point on the curve
    SK = SK1 * SK2  # SK is a point on the curve
    C1prime = C1 * (pair(C0, SK) / pair(C3, PK['P1']))  # C1' = C1 * (e(C0, SK) / e(C3, P1))
    C2prime = {}  # C2' is a dictionary
    for attribute in attributes:
        r = self.group.random()  # r is a random number
        C2prime[attribute] = C2[attribute] * (PK['A'][attribute] ** r)  # C2'[attribute] = C2[attribute] * (A[attribute]^r)
        C1prime *= (PK['P0'] ** r)  # C1' = C1' * P0^r
    C3prime = self.hashDate(H, date) ** SK  # C3' = H(date)^SK
    return { 'C0': C0, 'C1': C1prime, 'C2': C2prime, 'C3': C3prime }

def combine(self, PK, CTlist):
    '''Combine a list of ciphertexts into a single ciphertext'''
    C0 = CTlist[0]['C0']  # C0 is a point on the curve
    C1 = CTlist[0]['C1']  # C1 is a point on the curve
    C2 = {}  # C2 is a dictionary
    for attribute in CTlist[0]['C2']:
        C2[attribute] = CTlist[0]['C2'][attribute]  # C2[attribute] = C2[attribute]
    C3 = CTlist[0]['C3']  # C3 is a point on the curve
    for i in range(1, len(CTlist)):
        C1 *= CTlist[i]['C1']  # C1 = C1 * CTlist[i]['C1']
        C3 *= CTlist[i]['C3']  # C3 = C3 * CTlist[i]['C3']
        for attribute in CTlist[i]['C2']:
            C2[attribute] *= CTlist[i]['C2'][attribute]  # C2[attribute] = C2[attribute] * CTlist[i]['C2'][attribute]
    return { 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3 }

def generateUserKey(self, PK, MK, H, user):
    '''Generate a user key for a user'''
    SK1 = MK['SK1']  # SK1 is a point on the curve
    SK2 = MK['A'][user]  # SK2 is a point on the curve
    SK = SK1 * SK2  # SK is a point on the curve
    return SK

def generateUserKeys(self, PK, MK, H, users):
    '''Generate user keys for a list of users'''
    SK1 = MK['SK1']  # SK1 is a point on the curve
    SK = {}  # SK is a dictionary
    for user in users:
        SK2 = MK['A'][user]  # SK2 is a point on the curve
        SK[user] = SK1 * SK2  # SK[user] = SK1 * SK2
    return SK

def hashDate(self, H, date):
    '''Hash a date to a point on the curve'''
    return H(date)  # return H(date)

def hashAttributes(self, H, attributes):
    '''Hash a list of attributes to a point on the curve'''
    return H(attributes)  # return H(attributes)

def hashMessage(self, H, message):
    '''Hash a message to a point on the curve'''
    return H(message)  # return H(message)

def hashPK(self, H, PK):
    '''Hash a public key to a point on the curve'''
    return H(PK)  # return H(PK)

def hashSK(self, H, SK):
    '''Hash a secret key to a point on the curve'''
    return H(SK)  # return H(SK)

def hashMK(self, H, MK):
    '''Hash a master key to a point on the curve'''
    return H(MK)  # return H(MK)

def hashCiphertext(self, H, CT):
    '''Hash a ciphertext to a point on the curve'''
    return H(CT)  # return H(CT)

def hashSignature(self, H, signature):
    '''Hash a signature to a point on the curve'''
    return H(signature)  # return H(signature)

def hash(self, H, message):
    '''Hash a message to a point on the curve'''
    return H(message)  # return H(message)

def sign(self, SK, H, message):
    '''Sign a message'''
    return H(message) ** SK  # return H(message)^SK

def verify(self, PK, H, message, signature):
    '''Verify a signature'''
    return (H(message) == signature)  # return H(message) == signature

def encrypt(self, PK, H, message):
    '''Encrypt a message'''
    r = self.group.random()  # r is a random number
    C0 = PK['P0'] ** r  # C0 = P0^r
    C1 = PK['P1'] ** r  # C1 = P1^r
    C2 = H(message) ** r  # C2 = H(message)^r
    return { 'C0': C0, 'C1': C1, 'C2': C2 }

def decrypt(self, PK, SK, CT):
    '''Decrypt a ciphertext'''
    C0 = CT['C0']  # C0 is a point on the curve
    C1 = CT['C1']  # C1 is a point on the curve
    C2 = CT['C2']  # C2 is a point on the curve
    return (C2 / (C0 ** SK)) / C1  # return (C2 / (C0^SK)) / C1

def generateRandom(self, PK, H):
    '''Generate a random point on the curve'''
    return H(self.group.random())  # return H(random)

def generateRandomExponent(self, PK, H):
    '''Generate a random exponent'''
    return self.group.random()  # return random

def generateRandomExponents(self, PK, H, n):
    '''Generate a list of random exponents'''
    return [self.group.random() for i in range(n)]  # return [random for i in range(n)]