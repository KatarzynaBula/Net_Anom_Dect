sorted_list1 = [1, 2, 3, 4, 5, 6, 7, 8, 9]
def binarySearch(num, sorted_list):
    start = 0
    end = len(sorted_list)-1

    while start <= end:
        mid = (start + end) // 2
        if (num > sorted_list[mid]):
            start = mid + 1
        elif (num < sorted_list[mid]):
            end = mid - 1
        else:
            return mid
    return None
    
print(binarySearch(3, sorted_list1))
