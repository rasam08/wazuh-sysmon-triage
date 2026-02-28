import React, { useEffect, useMemo, useRef, useState } from 'react';
import type { Core } from 'cytoscape';
import type { ProcessTree } from '@/types';

interface ProcessTreeGraphProps {
  tree: ProcessTree;
  monospaceCommands: boolean;
}

function shortImageName(image: string): string {
  const parts = image.split('\\');
  return parts[parts.length - 1] || image;
}

export function ProcessTreeGraph({ tree, monospaceCommands }: ProcessTreeGraphProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const [selectedGuid, setSelectedGuid] = useState<string | null>(tree.nodes[0]?.guid ?? null);

  const selectedNode = useMemo(
    () => tree.nodes.find((node) => node.guid === selectedGuid) ?? null,
    [tree.nodes, selectedGuid],
  );

  const elements = useMemo(() => {
    const nodes = tree.nodes.map((node) => ({
      data: {
        id: node.guid,
        label: shortImageName(node.image),
        pid: node.pid,
        image: node.image,
        cmdline: node.cmdline,
        user: node.user,
        tags: node.tags,
        synthetic: node.synthetic ? 1 : 0,
      },
    }));

    const edges = tree.edges.map((edge, index) => ({
      data: {
        id: `edge-${index}-${edge.parent_guid}-${edge.child_guid}`,
        source: edge.parent_guid,
        target: edge.child_guid,
        label: edge.reason || 'spawned',
      },
    }));

    return [...nodes, ...edges];
  }, [tree.edges, tree.nodes]);

  useEffect(() => {
    if (import.meta.env.MODE === 'test') return;

    let cancelled = false;
    const mount = async () => {
      if (!containerRef.current) return;
      const { default: cytoscape } = await import('cytoscape');
      if (cancelled || !containerRef.current) return;

      const cy = cytoscape({
        container: containerRef.current,
        elements,
        style: [
          {
            selector: 'node',
            style: {
              'background-color': '#3b82f6',
              label: 'data(label)',
              color: '#e5e7eb',
              'font-size': '10px',
              'text-wrap': 'wrap',
              'text-max-width': '100px',
              'text-valign': 'bottom',
              'text-margin-y': '8px',
              width: '28px',
              height: '28px',
              'border-color': '#1f2937',
              'border-width': '1px',
            },
          },
          {
            selector: 'node[synthetic = 1]',
            style: {
              'background-color': '#6b7280',
            },
          },
          {
            selector: 'edge',
            style: {
              width: '1.2px',
              'line-color': '#4b5563',
              'target-arrow-color': '#4b5563',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              label: 'data(label)',
              color: '#9ca3af',
              'font-size': '9px',
              'text-background-color': '#111827',
              'text-background-opacity': 1,
              'text-background-padding': '2px',
            },
          },
          {
            selector: 'node:selected',
            style: {
              'border-width': '3px',
              'border-color': '#22d3ee',
              'background-color': '#06b6d4',
            },
          },
        ] as any,
        layout: {
          name: tree.edges.length > 0 ? 'breadthfirst' : 'grid',
          directed: true,
          padding: 28,
          spacingFactor: 1.1,
        },
        wheelSensitivity: 0.15,
      });

      cy.on('tap', 'node', (event) => {
        const nodeId = event.target.id();
        setSelectedGuid(nodeId);
      });

      cy.fit(undefined, 28);
      cyRef.current = cy;
    };

    void mount();
    return () => {
      cancelled = true;
      cyRef.current?.destroy();
      cyRef.current = null;
    };
  }, [elements, tree.edges.length]);

  useEffect(() => {
    if (!cyRef.current || !selectedGuid) return;
    const target = cyRef.current.getElementById(selectedGuid);
    if (target.nonempty()) {
      cyRef.current.elements().unselect();
      target.select();
    }
  }, [selectedGuid]);

  useEffect(() => {
    if (!selectedGuid && tree.nodes.length > 0) {
      setSelectedGuid(tree.nodes[0].guid);
    }
  }, [selectedGuid, tree.nodes]);

  if (!tree.nodes.length) {
    return <p className="text-sm text-gray-500">No process tree nodes available.</p>;
  }

  return (
    <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)] gap-3">
      <div className="rounded-lg border border-gray-800 bg-gray-900/60 h-[420px]">
        <div ref={containerRef} className="w-full h-full" aria-label="Process tree graph" />
      </div>
      <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-3">
        {selectedNode ? (
          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-gray-200">Selected Process</h4>
            <p className={`text-xs text-gray-300 ${monospaceCommands ? 'font-mono' : ''}`}>{selectedNode.image}</p>
            <p className="text-xs text-gray-500">PID {selectedNode.pid} | {selectedNode.user}</p>
            <p className={`text-xs text-gray-400 break-all ${monospaceCommands ? 'font-mono' : ''}`}>
              {selectedNode.cmdline}
            </p>
            {selectedNode.tags.length > 0 && (
              <p className="text-xs text-cyan-300">Tags: {selectedNode.tags.join(', ')}</p>
            )}
          </div>
        ) : (
          <p className="text-xs text-gray-500">Select a process node to inspect details.</p>
        )}
      </div>
    </div>
  );
}
