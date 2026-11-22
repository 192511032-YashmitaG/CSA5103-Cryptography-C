# EXP 29: SHA-3 capacity lanes for a 1024-bit block
state_size=1600
block_size=1024
capacity=state_size-block_size
lane_size=64
capacity_lanes=capacity//lane_size
state=[0]*(state_size//lane_size)
print("State size:",state_size)
print("Block size:",block_size)
print("Capacity:",capacity)
print("Capacity lanes:",capacity_lanes)
print("Initial capacity lanes:",state[-capacity_lanes:])
print("Ignoring permutation, input absorption does not directly change the capacity lanes.")
