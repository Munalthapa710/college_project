coordinates = {
    'A': (27.7172, 85.3240),  
    'B': (27.7007, 85.3001),  
    'C': (27.6730, 85.3134),  
    'D': (27.7148, 85.3442),  
    'E': (27.6869, 85.3134),  
    'F': (27.7250, 85.3150)   
}

# Graph representing network connectivity and "distance" or "cost" between nodes
# This is used by Dijkstra algorithm.
# Ensure all nodes used as keys here are also in the `coordinates` dictionary.
# Ensure all nodes used as values in the inner dictionaries are also top-level keys.
graph = {
    'A': {'B': 2.5, 'F': 1.0},
    'B': {'A': 2.5, 'C': 3.0, 'D': 4.5},
    'C': {'B': 3.0, 'E': 1.5, 'D': 2.8},
    'D': {'B': 4.5, 'C': 2.8, 'F': 3.5},
    'E': {'C': 1.5},
    'F': {'A': 1.0, 'D': 3.5}
}

# Ensure all nodes in graph keys are in coordinates
for node in graph:
    if node not in coordinates:
        print(f"CRITICAL WARNING: Node '{node}' from graph is MISSING in coordinates dictionary!")
    for neighbor in graph[node]:
        if neighbor not in coordinates:
            print(f"CRITICAL WARNING: Neighbor node '{neighbor}' (of '{node}') from graph is MISSING in coordinates dictionary!")
        if neighbor not in graph: # Also check if neighbor is a top-level key in graph for consistency
             print(f"CRITICAL WARNING: Neighbor node '{neighbor}' (of '{node}') from graph is not a top-level key in graph itself!")