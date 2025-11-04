import heapq
def dijkstra(graph, start_node, end_node):
    if start_node not in graph or end_node not in graph or not graph.get(start_node): #graph as dictionary and other in string
        return float('inf')

    distances = {node: float('inf') for node in graph}
    distances[start_node] = 0
    priority_queue = [(0, start_node)] 

    while priority_queue:
        current_distance, current_node = heapq.heappop(priority_queue) #removes and returns the item with the smallest distance from the queue

        if current_distance > distances[current_node]: # optimization. It's possible for a node to be added to the queue multiple times with different distances. This check ensures we only process a node if we've found a genuinely new, shorter path to it.
            continue 

        if current_node == end_node: # A performance optimization. If the node we just popped from the queue is our target end_node, we know we've found the shortest possible path to it. We can stop the algorithm early and return the final distance.
            return distances[end_node]

        if current_node not in graph or not graph[current_node]: #Another safety check to handle malformed graphs. If the current node has no outgoing edges, we can't explore from it, so we skip to the next iteration.
            continue

        for neighbor, weight in graph[current_node].items(): #this core logic of the algorithm. We loop through all the neighbors of the current_node and their corresponding edge weights.
            if neighbor not in graph:  # ensure the neighbor node exists in the graph.
                continue
            distance = current_distance + weight # Calculates the potential new distance to this neighbor by taking the distance to get to the current_node and adding the weight of the edge connecting them.
            if distance < distances[neighbor]: #This is the "relaxation" step.
                distances[neighbor] = distance # If the new path is shorter, we update our distances 
                heapq.heappush(priority_queue, (distance, neighbor)) #We add the neighbor to the priority queue with its new, shorter distance
    
    return distances[end_node]   #If the while loop finishes (meaning all reachable nodes have been visited) and we haven't already returned from inside the loop, this line returns the final calculated shortest distance to our end_node.


def shortest_path(graph, start_node, end_node):
    if start_node not in graph or end_node not in graph or not graph.get(start_node):
        return []

    distances = {node: float('inf') for node in graph}
    predecessors = {node: None for node in graph}
    distances[start_node] = 0
    priority_queue = [(0, start_node)]
    path_found_for_end_node = False

    while priority_queue:
        current_distance, current_node = heapq.heappop(priority_queue)

        if current_distance > distances[current_node]:
            continue
        if current_node == end_node:
            path_found_for_end_node = True
            break 
        if current_node not in graph or not graph[current_node]:
            continue
        for neighbor, weight in graph[current_node].items():
            if neighbor not in graph:  #This is the crucial line inside the loop. When we find a shorter path to a neighbor, we not only update its distance but we also record that the current_node is its predecessor or parent on this new shortest path.
                continue
            distance = current_distance + weight
            if distance < distances[neighbor]: #if path isnt found
                distances[neighbor] = distance
                predecessors[neighbor] = current_node
                heapq.heappush(priority_queue, (distance, neighbor))
    
    if not path_found_for_end_node or distances[end_node] == float('inf'): #This begins the path reconstruction. We start a new list called path and set our current position to our destination, the end_node.
        return [] 
    path = [] 
    current = end_node
    while current is not None: #backward loop add current node to path list ,lookup predicessor and set current predecessor loop continue until current become none.
        path.append(current)
        current = predecessors[current]
    return path[::-1] #The path we constructed is backward. path[::-1] is a Python that reverses the list. It returns the final, correct path