function updateSankey() {
    fetch('http://localhost:5000/get_packet_data')
        .then(response => response.json())
        .then(data => {
            const parsedData = JSON.parse(data);
            const nodesMap = new Map(); // To hold unique nodes
            const links = []; // To hold the source-target-value relationship

            // Iterate over the data to populate nodes and links
            parsedData.forEach(packet => {
                const source = packet.src;
                const target = packet.dst;
                const value = packet.len;

                // If the source node is new, add it to nodesMap
                if (!nodesMap.has(source)) {
                    nodesMap.set(source, nodesMap.size);
                }

                // If the target node is new, add it to nodesMap
                if (!nodesMap.has(target)) {
                    nodesMap.set(target, nodesMap.size);
                }

                // Find or create the link between source and target
                const linkIndex = links.findIndex(link => link.source === nodesMap.get(source) && link.target === nodesMap.get(target));
                if (linkIndex !== -1) {
                    // Link exists, update its value
                    links[linkIndex].value += value;
                } else {
                    // Create a new link
                    links.push({
                        source: nodesMap.get(source),
                        target: nodesMap.get(target),
                        value: value
                    });
                }
            });

            // Convert nodesMap to an array for Plotly
            const nodes = Array.from(nodesMap.keys());

            // Render Sankey diagram using Plotly
            Plotly.react('sankeyDiagram', {
                data: [{
                    type: 'sankey',
                    orientation: 'h',
                    node: {
                        pad: 15,
                        thickness: 30,
                        line: {
                            color: 'black',
                            width: 0.5
                        },
                        label: nodes
                    },
                    link: {
                        source: links.map(link => link.source),
                        target: links.map(link => link.target),
                        value: links.map(link => link.value)
                    }
                }],
                layout: {
                    title: 'Real-time Network Traffic Flow',
                    font: {
                        size: 12
                    }
                }
            });
        })
        .catch(error => console.error('Error fetching data:', error));
}

// Initial update
updateSankey();

// Set interval for continuous updates
setInterval(updateSankey, 2000);  // Update the diagram every 2 seconds
