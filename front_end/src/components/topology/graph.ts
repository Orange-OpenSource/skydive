import * as d3 from 'd3';

export interface Message {
    Obj: any;
    Type: string;
    Status: number;
}

export class Group {
    ID: string;
    Type: string;
    Nodes: { [key: string]: GNode };
    Hulls: [number, number] [];
    constructor(ID, type) {
        this.ID = ID;
        this.Type = type;
        this.Nodes = {};
        this.Hulls = [];
    }
}

export interface Metadata {
    [key: string]: string;
}

export class GNode implements d3.layout.force.Node {
    ID: string;
    Host: string;
    Metadata: Metadata;
    Edges: { [key: string]: Edge };
    Visible: boolean;
    Collapsed: boolean;
    Highlighted: boolean;
    Group: string;
    Graph: Graph;

    x: number;
    y: number;
    fixed: boolean;

    constructor(ID: string) {
        this.ID = ID;
        this.Host = '';
        this.Metadata = {};
        this.Edges = {};
        this.Visible = true;
        this.Collapsed = false;
        this.Highlighted = false;
        this.Group = '';
    };



    IsCaptureOn() {
        return 'Capture/ID' in this.Metadata;
    }

    IsCaptureAllowed() {
        let allowedTypes = ['device', 'veth', 'ovsbridge',
            'internal', 'tun', 'bridge'];
        return allowedTypes.indexOf(this.Metadata.Type) >= 0;
    }
}

export class Edge {
    ID: string;
    Host: string;
    Metadata: Metadata;
    Parent: GNode;
    Child: GNode;
    Visible: boolean;
    Graph: Graph;

    constructor(ID) {
        this.ID = ID;
        this.Host = '';
        this.Metadata = {};
        this.Visible = true;
    }
}

export class Graph {
    Nodes: { [key: string]: GNode };
    Edges: { [key: string]: Edge };
    Groups: { [key: string]: Group };
    
    constructor() {
        this.Nodes = {};
        this.Edges = {};
        this.Groups = {};
    };

    NewNode(ID: string, host?: string) {
        let node = new GNode(ID);
        node.Graph = this;
        node.Host = host;

        this.Nodes[ID] = node;

        return node;
    };

    GetNode(ID) {
        return this.Nodes[ID];
    };

    GetNeighbors(node) {
        let neighbors = [];

        for (let i in node.Edges) {
            neighbors.push(node.Edges[i]);
        }

        return neighbors;
    };

    GetChildren(node) {
        let children = [];

        for (let i in node.Edges) {
            let e = node.Edges[i];
            if (e.Parent === node)
                children.push(e.Child);
        }

        return children;
    };

    GetParents(node) {
        let parents = [];

        for (let i in node.Edges) {
            let e = node.Edges[i];
            if (e.Child === node)
                parents.push(e.Child);
        }

        return parents;
    };

    GetEdge(ID) {
        return this.Edges[ID];
    };

    NewEdge(ID, parent, child, host) {
        let edge = new Edge(ID);
        edge.Parent = parent;
        edge.Child = child;
        edge.Graph = this;
        edge.Host = host;

        this.Edges[ID] = edge;

        parent.Edges[ID] = edge;
        child.Edges[ID] = edge;

        return edge;
    };

    DelNode(node) {
        for (let i in node.Edges) {
            this.DelEdge(this.Edges[i]);
        }

        delete this.Nodes[node.ID];
    };

    DelEdge(edge) {
        delete edge.Parent.Edges[edge.ID];
        delete edge.Child.Edges[edge.ID];
        delete this.Edges[edge.ID];
    };

    InitFromSyncMessage(msg: Message) {
        let g = msg.Obj;

        let i;
        for (i in g.Nodes || []) {
            let n = g.Nodes[i];

            let node = this.NewNode(n.ID, n.Host);
            if ('Metadata' in n)
                node.Metadata = n.Metadata;
        }

        for (i in g.Edges || []) {
            let e = g.Edges[i];

            let parent = this.GetNode(e.Parent);
            let child = this.GetNode(e.Child);

            if (!parent || !child)
                continue;

            let edge = this.NewEdge(e.ID, parent, child, e.Host);

            if ('Metadata' in e)
                edge.Metadata = e.Metadata;
        }
    }
}
