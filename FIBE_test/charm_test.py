from charm.toolbox.pairinggroup import PairingGroup,G1
group = PairingGroup('SS512')
data = 'just for test'
h = group.hash(data)
print(type(h),h)
