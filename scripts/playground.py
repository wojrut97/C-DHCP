
dict = {}

mesage = [1, 3, 5]
if mesage[1] not in dict:
        dict[mesage[1]] = [mesage]

mesage2 = [4, 5, 6]

if mesage2[1] not in dict:
        dict[mesage2[1]] = [mesage2]

dict[3].append(mesage)

print(dict)