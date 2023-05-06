#import FIBElib.py來執行FIBE的簡單測試，初始化後註冊一個DO Alice兩個DU Bob、Cherry加密一個檔案"hello world"Alice以及Bob擁有存取權
from FIBElib import *   # import FIBElib.py
from charm.toolbox.ABEnc import Input, Output
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.ABEnc import Input, Output

from functools import reduce

#This is an example for calling this function: from FIBElib import *
group = PairingGroup('SS512')
util = SecretUtil(group, verbose=False)

attributes = ['Alice', 'Bob', 'Cherry']
(PK, MK, H) = setup(group, attributes)
print("PK =>", PK)
print("MK =>", MK)
print("H =>", H)
