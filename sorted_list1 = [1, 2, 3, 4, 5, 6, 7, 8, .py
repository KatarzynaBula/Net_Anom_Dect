def merge(a, b):

    index_a = 0
    index_b = 0
    c = []
    while index_a < len(a) and index_b < len(b):
        if a[index_a] <= b[index_b]:
            c.append(a[index_a])
            index_a = index_a + 1
        else:
            c.append(b[index_b])
            index_b = index_b + 1
 
    c.extend(a[index_a:])
    c.extend(b[index_b:])
    return c




def mergesort(list):
    if len(list) == 0 or len(list) == 1: 
        return list[:len(list)] 
    #recursion
    halfway = len(list) // 2
    list1 = list[0:halfway]
    list2 = list[halfway:len(list)]
    newlist1 = mergesort(list1) 
    newlist2 = mergesort(list2) 
    newlist = merge(newlist1, newlist2)
    return newlist

list1 = [4, 7, 2, 9]
print(mergesort(list1))
