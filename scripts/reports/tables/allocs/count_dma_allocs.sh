#!/bin/bash

KERNEL=${KERNEL:-$(readlink -f ../../../../kdfsan-df-linux)}
echo "Counting DMA allocs in kernel source tree '$KERNEL'..." >&2
cd $KERNEL

# Function to count DMA allocs in a single object file
count_dma_allocs() {
    local obj_file="$1"

    # Count the number of DMA allocs
    dma_allocs=$(nm -an "$obj_file" | grep -E ' [Uu] dfs\$dma_alloc_| [Uu] dfs\$dma_map_| [Uu] dfs\$dma_pool_alloc| [Uu] dfs\$__dma_map_| [Uu] dfs\$dmam_alloc_' | wc -l)

    # If there are any DMA allocs, output the result
    if [ "$dma_allocs" -gt 0 ]; then
        # Remove the leading './' and print the result directly
        echo "${obj_file#./}, $dma_allocs"
    fi
}

export -f count_dma_allocs  # Export the function for use in parallel

# Find all object files, excluding specified ones, then count DMA allocs in parallel, then sort
find . -name '*.o' ! -wholename './kernel/dma/mapping.o' ! -wholename './mm/dmapool.o' ! -wholename './vmlinux.o' ! -wholename './lib/test_kdfsan_policies.o' | parallel count_dma_allocs | sort

