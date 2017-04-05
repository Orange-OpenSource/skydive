/* jshint multistr: true */
import * as d3 from "d3"
import Vue from 'vue';
import { Component, Watch } from 'vue-property-decorator';

@Component({
  template: require("./conversation.html")
})

export class ConversationComponent extends Vue {
  layout: ConversationLayout;

  name = 'Conversation';
  layers: {label:string, value: string} [];
  orders: {label:string, value: string} []
  layer: string;
  order: string;
  node: {};

  data() {
    return {
      layers: [
        {label: "Ethernet", value: "ethernet"},
        {label: "IPv4", value: "ipv4"},
        {label: "IPv6", value: "ipv6"},
        {label: "TCP", value: "tcp"},
        {label: "UDP", value: "udp"},
        {label: "SCTP", value: "sctp"},
      ],
      layer: "ethernet",
      orders: [
        {label: "by Name", value: "name"},
        {label: "by Frequency", value: "count"},
        {label: "by Application", value: "group"},
      ],
      order: "name",
      node: null,
    };
  }


  mounted() {
    this.layout = new ConversationLayout(this, ".conversation-d3");
    this.layout.ShowConversation("ethernet");
  }

  @Watch('layer')
  watchLayer() {
    this.layout.ShowConversation(this.layer);
  }

  @Watch('order')
  watchOrder() {
    this.layout.Order(this.order);
  }

};

interface Cell {
  x: number;
  y: number;
  z: number;
}

class ConversationLayout {
  vm: { node: any };
  svg: d3.Selection<any>;
  width: number;
  height: number;
  orders: { name?: number[], count?: number[], group?: number[] };

  constructor(vm, selector) {
    this.vm = vm;
    this.width = 600;
    this.height = 600;

    var margin = { top: 100, right: 0, bottom: 10, left: 100 };

    this.svg = d3.select(selector).append("svg")
      .attr("width", this.width + margin.left + margin.right)
      .attr("height", this.height + margin.top + margin.bottom)
      .style("margin-left", -margin.left + 20 + "px")
      .append("g")
      .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

    this.orders = {};
  }

  Order(order) {
    if (!(order in this.orders))
      return;

    var x = d3.scale.ordinal().rangeBands([0, this.width]);

    x.domain(this.orders[order]);

    var t = this.svg.transition().duration(2500);

    t.selectAll(".row")
      .delay(function (d, i) { return x(i + '') * 4; })
      .attr("transform", function (d, i) {
        return "translate(0," + x(i + '') + ")";
      })
      .selectAll(".cell")
      .delay(function (d) { return x(d.x) * 4; })
      .attr("x", function (d) { return x(d.x); });

    t.selectAll(".column")
      .delay(function (d, i) { return x(i + '') * 4; })
      .attr("transform", function (d, i) {
        return "translate(" + x(i + '') + ")rotate(-90)";
      });
  };

  NodeDetails(node) {
    this.vm.node = node;
  }

  ShowConversation(layer) {
    this.svg.selectAll("*").remove();

    var _this = this;
    d3.json("/api/flow/conversation/" + layer, function (data) {
      var matrix = [];
      var nodes = data.nodes;
      var n = nodes.length;

      // Compute index per node.
      nodes.forEach(function (node, i) {
        node.index = i;
        node.count = 0;
        matrix[i] = d3.range(n).map(function (j) { return { x: j, y: i, z: 0 }; });
      });

      // Convert links to matrix; count character occurrences.
      data.links.forEach(function (link) {
        matrix[link.source][link.target].z += link.value;
        matrix[link.target][link.source].z += link.value;
        nodes[link.source].count += link.value;
        nodes[link.target].count += link.value;
      });

      // Precompute the orders.
      _this.orders = {
        name: d3.range(n).sort(function (a, b) {
          return d3.ascending(nodes[a].name, nodes[b].name);
        }),
        count: d3.range(n).sort(function (a, b) {
          return nodes[b].count - nodes[a].count;
        }),
        group: d3.range(n).sort(function (a, b) {
          return nodes[b].group - nodes[a].group;
        })
      };

      var x = d3.scale.ordinal().rangeBands([0, _this.width]);
      var z = d3.scale.linear().domain([0, 4]).clamp(true);
      var c = d3.scale.category10().domain(d3.range(10).map(function (x) { return x + '' }));

      // The default sort order.
      x.domain(_this.orders.name.map(function (x) { return x + '' }));

      _this.svg.append("rect")
        .attr("class", "background")
        .attr("width", _this.width)
        .attr("height", _this.height);

      var row = _this.svg.selectAll(".row")
        .data(matrix)
        .enter().append("g")
        .attr("class", "row")
        .attr("transform", function (d, i) {
          return "translate(0," + x('' + i) + ")";
        })
        .each(function (row) {
          var cell = d3.select(this).selectAll(".cell")
            .data<Cell>(row.filter(function (d) { return d.z; }))
            .enter().append("rect")
            .attr("class", "cell")
            .attr("x", function (d) { return x('' + d.x); })
            .attr("width", x.rangeBand())
            .attr("height", x.rangeBand())
            .style("fill-opacity", function (d) { return z(d.z); })
            .style("fill", function (d) { return "rgb(31, 119, 180)"; })
            .on("mouseover", function (p) {
              d3.selectAll(".row text").classed("active", function (d, i) { return i == p.y; });
              d3.selectAll(".column text").classed("active", function (d, i) { return i == p.x; });
              //_this.NodeDetails(nodes[p.x]);
            })
            .on("mouseout", function (p) {
              d3.selectAll("text").classed("active", false);
            });
        });

      row.append("line")
        .attr("x2", _this.width);

      row.append("text")
        .attr("x", -6)
        .attr("y", x.rangeBand() / 2)
        .attr("dy", ".32em")
        .attr("text-anchor", "end")
        .text(function (d, i) { return nodes[i].name; });

      var column = _this.svg.selectAll(".column")
        .data(matrix)
        .enter().append("g")
        .attr("class", "column")
        .attr("transform", function (d, i) {
          return "translate(" + x('' + i) + ")rotate(-90)";
        });

      column.append("line")
        .attr("x1", -_this.width);

      column.append("text")
        .attr("x", 6)
        .attr("y", x.rangeBand() / 2)
        .attr("dy", ".32em")
        .attr("text-anchor", "start")
        .text(function (d, i) { return nodes[i].name; });
    });
  }
}
