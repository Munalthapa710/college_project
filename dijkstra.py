# dijkstra.py
import heapq

def dijkstra(graph, start_node, end_node):
    if start_node not in graph or end_node not in graph or not graph.get(start_node):
        return float('inf')

    distances = {node: float('inf') for node in graph}
    distances[start_node] = 0
    priority_queue = [(0, start_node)] 

    while priority_queue:
        current_distance, current_node = heapq.heappop(priority_queue)

        if current_distance > distances[current_node]:
            continue 

        if current_node == end_node:
            return distances[end_node]

        if current_node not in graph or not graph[current_node]: 
            continue

        for neighbor, weight in graph[current_node].items():
            if neighbor not in graph: 
                continue
            distance = current_distance + weight
            if distance < distances[neighbor]:
                distances[neighbor] = distance
                heapq.heappush(priority_queue, (distance, neighbor))
    
    return distances[end_node]


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
            if neighbor not in graph:
                continue
            distance = current_distance + weight
            if distance < distances[neighbor]:
                distances[neighbor] = distance
                predecessors[neighbor] = current_node
                heapq.heappush(priority_queue, (distance, neighbor))
    
    if not path_found_for_end_node or distances[end_node] == float('inf'):
        return [] 
    path = []
    current = end_node
    while current is not None:
        path.append(current)
        current = predecessors[current]
    return path[::-1]