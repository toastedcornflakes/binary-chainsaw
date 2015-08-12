import array
import itertools


def make_bytearray(n, undefined_value):
    return array.array('B', itertools.repeat(undefined_value, n))


class SparseBytes():
    """ A page-based sparse array. The content is backed by a dict() (of array.array('B') by default)"""

    def __init__(self, pagesize=4096, undefined_value=0,
                 array_constructor=None):
        assert isinstance(pagesize, int), "pagesize must be integer"
        assert isinstance(
            undefined_value, int) and undefined_value % 255 == undefined_value, "undefined_value must be a byte"

        if array_constructor:
            self.array_constructor = array_constructor
        else:
            # set default constructor to array.array('B')
            self.array_constructor = make_bytearray
        self.pages = dict()
        self.pagesize = pagesize
        self.undefined_value = undefined_value

    def __getitem__(self, index):
        assert isinstance(index, int), "indices must be integers"

        dict_index = index // self.pagesize
        array_index = index % self.pagesize

        bytes_ = self.pages[dict_index]
        return bytes_[array_index]

    def __setitem__(self, index, item):
        assert isinstance(index, int), "indices must be integers"

        dict_index = index // self.pagesize
        array_index = index % self.pagesize

        try:
            bytes_ = self.pages[dict_index]
        except KeyError:
            bytes_ = self.__makePage(dict_index)
        bytes_[array_index] = item

    def bytes_at(self, index, length):
        """ Return a bytearray of the content starting at index
            and ending at index + length - 1"""
        ps = self.pagesize
        if (index + length) // ps == index // ps:
            p = self.pages[index // ps]
            return bytes(p[index % ps: (index + length) % ps])

        l = bytearray()
        for i in range(index, index + length - 1):
            try:
                l.append(self[i])
            except KeyError:
                break
        return bytes(l)

    def __makePage(self, index):
        """ Fills a page bytes """
        bytes_ = self.array_constructor(self.pagesize, self.undefined_value)
        self.pages[index] = bytes_
        return bytes_
