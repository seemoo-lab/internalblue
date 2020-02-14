class Queue_Element:
    index = 0
    next_item = 0
    prev = 0
    capacity = 0
    name = ''
    queue_buf_start = 0
    available_items = 0
    item_size = 0
    next_free_slot = 0
    free_slots = 0
    address = 0
    waitlist_length = 0
    next = 0
    queue_buf_end = 0
    thread_waitlist = 0

    def __init__(self, index, address, item_size, capacity, available_items, free_slots, queue_buf_start, queue_buf_end,
                 next_item, next_free_slot, thread_waitlist, waitlist_length, next, prev, name):
        self.index = index
        self.next_item = next_item
        self.prev = prev
        self.capacity = capacity
        self.name = name
        self.queue_buf_start = queue_buf_start
        self.available_items = available_items
        self.item_size = item_size
        self.next_free_slot = next_free_slot
        self.free_slots = free_slots
        self.address = address
        self.waitlist_length = waitlist_length
        self.next = next
        self.queue_buf_end = queue_buf_end
        self.thread_waitlist = thread_waitlist

    def __getitem__(self, item):
        # type: (str) -> Any
        return vars(self)[item]