/* Minimal SVG charting, hand-rolled - no chart library, no CDN, works offline.
 *
 * Design rules applied (see styles.css header for the palette validation):
 *   - thin marks, 4px rounded data-ends anchored to the baseline
 *   - a 2px surface gap between adjacent bars and between stacked segments
 *   - recessive axes and grid; text wears text tokens, never the series colour
 *   - a legend is always present for >= 2 series, and every mark carries a
 *     direct numeric label, so identity is never colour-alone
 *   - a per-mark hover tooltip on every bar
 *   - counts are integers, so the axis never invents fractional ticks
 */

var Charts = (function () {
  "use strict";

  var W = 720;                        // internal coordinate width
  var SVG_NS = "http://www.w3.org/2000/svg";

  function node(name, attrs, text) {
    var element = document.createElementNS(SVG_NS, name);
    for (var key in attrs) {
      if (attrs.hasOwnProperty(key)) element.setAttribute(key, attrs[key]);
    }
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  }

  function svgRoot(height) {
    var svg = node("svg", {
      viewBox: "0 0 " + W + " " + height,
      preserveAspectRatio: "xMidYMid meet",
      role: "img"
    });
    svg.style.height = "auto";
    return svg;
  }

  function tooltip(element, text) {
    element.appendChild(node("title", {}, text));
    element.style.transition = "opacity .12s";
    element.addEventListener("mouseenter", function () { element.style.opacity = "0.75"; });
    element.addEventListener("mouseleave", function () { element.style.opacity = "1"; });
    return element;
  }

  function empty(container, message) {
    container.innerHTML = "";
    var div = document.createElement("div");
    div.className = "empty";
    div.textContent = message || "No data yet. Analyse a domain to populate this view.";
    container.appendChild(div);
  }

  function legend(container, items) {
    var wrap = document.createElement("div");
    wrap.className = "legend";
    items.forEach(function (item) {
      var row = document.createElement("div");
      row.className = "legend-item";
      var swatch = document.createElement("span");
      swatch.className = "legend-swatch";
      swatch.style.background = item.color;
      row.appendChild(swatch);
      row.appendChild(document.createTextNode(item.label));
      wrap.appendChild(row);
    });
    container.appendChild(wrap);
  }

  /* ---- horizontal bars: magnitude by named category ---------------------
   * items: [{ label, value, color, note }]
   */
  function horizontalBars(container, items, options) {
    options = options || {};
    container.innerHTML = "";
    if (!items.length || items.every(function (i) { return !i.value; })) {
      return empty(container, options.emptyMessage);
    }

    var labelWidth = options.labelWidth || 150;
    var rowHeight = 30;
    var barHeight = 14;
    var gap = 2;                                   // surface gap between bars
    var valueWidth = 46;
    var trackWidth = W - labelWidth - valueWidth;
    var max = Math.max.apply(null, items.map(function (i) { return i.value; })) || 1;
    var height = items.length * rowHeight;

    var svg = svgRoot(height);

    items.forEach(function (item, index) {
      var y = index * rowHeight;
      var barY = y + (rowHeight - barHeight) / 2 + gap / 2;
      var width = Math.max(item.value > 0 ? 3 : 0, (item.value / max) * trackWidth);

      svg.appendChild(node("text", {
        x: labelWidth - 12, y: y + rowHeight / 2 + 4,
        "text-anchor": "end", "font-size": "12.5"
      }, item.label));

      svg.appendChild(node("rect", {
        x: labelWidth, y: barY, width: trackWidth, height: barHeight - gap,
        rx: 4, fill: "var(--bg-raised)"
      }));

      if (width > 0) {
        svg.appendChild(tooltip(node("rect", {
          x: labelWidth, y: barY, width: width, height: barHeight - gap,
          rx: 4, fill: item.color
        }), item.label + ": " + item.value + (item.note ? " (" + item.note + ")" : "")));
      }

      svg.appendChild(node("text", {
        x: labelWidth + trackWidth + 10, y: y + rowHeight / 2 + 4,
        "font-size": "12.5", "class": "val"
      }, item.value));
    });

    container.appendChild(svg);
    if (options.legend) legend(container, options.legend);
  }

  /* ---- vertical columns: distribution across ordered buckets ------------
   * items: [{ label, value, color, note }]
   */
  function columns(container, items, options) {
    options = options || {};
    container.innerHTML = "";
    if (!items.length || items.every(function (i) { return !i.value; })) {
      return empty(container, options.emptyMessage);
    }

    var plotHeight = 150;
    var labelBand = 34;
    var valueBand = 18;
    var height = plotHeight + labelBand + valueBand;
    var gap = 2;
    var slot = W / items.length;
    var barWidth = Math.min(48, slot - 8);
    var max = Math.max.apply(null, items.map(function (i) { return i.value; })) || 1;

    var svg = svgRoot(height);
    var baseline = valueBand + plotHeight;

    svg.appendChild(node("line", {
      x1: 0, y1: baseline, x2: W, y2: baseline, "class": "axis"
    }));

    items.forEach(function (item, index) {
      var centre = slot * index + slot / 2;
      var barHeight = item.value > 0
        ? Math.max(3, (item.value / max) * (plotHeight - 6)) : 0;
      var y = baseline - barHeight;

      if (barHeight > 0) {
        svg.appendChild(tooltip(node("rect", {
          x: centre - barWidth / 2 + gap / 2, y: y,
          width: barWidth - gap, height: barHeight,
          rx: 4, fill: item.color
        }), item.label + ": " + item.value + (item.note ? " " + item.note : "")));

        svg.appendChild(node("text", {
          x: centre, y: y - 6, "text-anchor": "middle",
          "font-size": "12", "class": "val"
        }, item.value));
      }

      svg.appendChild(node("text", {
        x: centre, y: baseline + 16, "text-anchor": "middle", "font-size": "11"
      }, item.label));

      if (item.sublabel) {
        svg.appendChild(node("text", {
          x: centre, y: baseline + 29, "text-anchor": "middle", "font-size": "10"
        }, item.sublabel));
      }
    });

    container.appendChild(svg);
    if (options.legend) legend(container, options.legend);
  }

  /* ---- stacked columns: composition over time --------------------------
   * buckets: [{ label, segments: [{ key, value, color }] }]
   */
  function stackedColumns(container, buckets, options) {
    options = options || {};
    container.innerHTML = "";
    var totals = buckets.map(function (b) {
      return b.segments.reduce(function (sum, s) { return sum + s.value; }, 0);
    });
    if (!buckets.length || totals.every(function (t) { return !t; })) {
      return empty(container, options.emptyMessage);
    }

    var plotHeight = 150;
    var labelBand = 26;
    var valueBand = 18;
    var height = plotHeight + labelBand + valueBand;
    var gap = 2;
    var slot = W / buckets.length;
    var barWidth = Math.min(44, slot - 8);
    var max = Math.max.apply(null, totals) || 1;

    var svg = svgRoot(height);
    var baseline = valueBand + plotHeight;

    svg.appendChild(node("line", {
      x1: 0, y1: baseline, x2: W, y2: baseline, "class": "axis"
    }));

    buckets.forEach(function (bucket, index) {
      var centre = slot * index + slot / 2;
      var cursor = baseline;

      bucket.segments.forEach(function (segment) {
        if (!segment.value) return;
        var segHeight = Math.max(3, (segment.value / max) * (plotHeight - 6));
        cursor -= segHeight;
        svg.appendChild(tooltip(node("rect", {
          x: centre - barWidth / 2 + gap / 2, y: cursor + gap / 2,
          width: barWidth - gap, height: Math.max(1, segHeight - gap),
          rx: 3, fill: segment.color
        }), bucket.label + " - " + segment.key + ": " + segment.value));
      });

      if (totals[index] > 0) {
        svg.appendChild(node("text", {
          x: centre, y: cursor - 6, "text-anchor": "middle",
          "font-size": "12", "class": "val"
        }, totals[index]));
      }

      // Thin out tick labels when buckets are dense.
      var step = Math.ceil(buckets.length / 12);
      if (index % step === 0) {
        svg.appendChild(node("text", {
          x: centre, y: baseline + 16, "text-anchor": "middle", "font-size": "10.5"
        }, bucket.label));
      }
    });

    container.appendChild(svg);
    if (options.legend) legend(container, options.legend);
  }

  return {
    horizontalBars: horizontalBars,
    columns: columns,
    stackedColumns: stackedColumns,
    empty: empty
  };
})();
