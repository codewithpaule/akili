(function () {
  const el = document.getElementById('graph-canvas');
  const w = el.clientWidth || 800;
  const h = el.clientHeight || 500;
  const nodes = [
    { id: 'example.com', type: 'domain', label: 'example.com' },
    { id: '203.0.113.1', type: 'ip', label: '203.0.113.1' },
    { id: 'Jane Doe', type: 'person', label: 'Jane Doe' },
    { id: 'Acme Corp', type: 'company', label: 'Acme Corp' },
    { id: 'admin@example.com', type: 'email', label: 'admin@' },
    { id: 'nginx', type: 'tech', label: 'nginx' },
  ];
  const links = [
    { source: 'example.com', target: '203.0.113.1' },
    { source: 'example.com', target: 'Jane Doe' },
    { source: 'Acme Corp', target: 'example.com' },
    { source: 'admin@example.com', target: 'example.com' },
    { source: '203.0.113.1', target: 'nginx' },
  ];
  const colors = { domain: '#2563EB', ip: '#059669', person: '#DB2777', company: '#D97706', email: '#0891B2', tech: '#64748B', cve: '#DC2626' };
  const svg = d3.select('#graph-canvas').append('svg').attr('width', w).attr('height', h);
  const g = svg.append('g');
  const zoom = d3.zoom().scaleExtent([0.3, 3]).on('zoom', (e) => g.attr('transform', e.transform));
  svg.call(zoom);
  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id((d) => d.id).distance(100))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(w / 2, h / 2));
  const link = g.append('g').selectAll('line').data(links).join('line').attr('stroke', '#475569').attr('stroke-width', 1);
  const node = g.append('g').selectAll('g').data(nodes).join('g').style('cursor', 'pointer')
    .call(d3.drag().on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));
  node.append('circle').attr('r', 14).attr('fill', (d) => colors[d.type] || '#94A3B8');
  node.append('text').attr('dy', 28).attr('text-anchor', 'middle').attr('fill', '#fff').attr('font-size', 10).text((d) => d.label);
  node.on('click', (_, d) => {
    document.getElementById('detail').innerHTML = `<span class="badge badge-info">${d.type}</span><h3>${AKILI.escapeHtml(d.label)}</h3><p>Connected entities from your scans appear here.</p><a href="scan-website.html" class="btn btn-primary btn-sm">Run Full Scan</a>`;
  });
  document.getElementById('reset')?.addEventListener('click', () => {
    nodes.forEach((n) => { n.fx = null; n.fy = null; });
    sim.alpha(1).restart();
  });

  sim.on('tick', () => {
    link.attr('x1', (d) => d.source.x).attr('y1', (d) => d.source.y).attr('x2', (d) => d.target.x).attr('y2', (d) => d.target.y);
    node.attr('transform', (d) => `translate(${d.x},${d.y})`);
  });
  document.getElementById('reset')?.addEventListener('click', () => sim.alpha(1).restart());
})();
