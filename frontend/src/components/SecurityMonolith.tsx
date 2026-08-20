import { useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Float } from '@react-three/drei';
import * as THREE from 'three';

function MonolithMesh() {
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (!meshRef.current) return;
    
    // Base automatic rotation
    const baseRotationY = state.clock.getElapsedTime() * 0.08;
    
    // Target rotation based on mouse coordinates (-1 to 1)
    const targetX = state.mouse.y * 0.25; // X-axis rotation is vertical mouse shift
    const targetY = state.mouse.x * 0.25 + baseRotationY; // Y-axis rotation is horizontal mouse shift + automatic rotate
    
    // Smoothly lerp towards targets
    meshRef.current.rotation.x = THREE.MathUtils.lerp(meshRef.current.rotation.x, targetX, 0.05);
    meshRef.current.rotation.y = THREE.MathUtils.lerp(meshRef.current.rotation.y, targetY, 0.05);
  });

  return (
    <Float speed={1.2} rotationIntensity={0.15} floatIntensity={0.4}>
      <mesh ref={meshRef}>
        {/* A sleek, sharp, abstract monolith geometry */}
        <boxGeometry args={[1.4, 3.0, 0.25]} />
        <meshPhysicalMaterial 
          color="#0d0d0d"
          metalness={0.95}
          roughness={0.15}
          clearcoat={1.0}
          clearcoatRoughness={0.1}
          reflectivity={0.9}
        />
      </mesh>
    </Float>
  );
}

export default function SecurityMonolith() {
  return (
    <div className="absolute inset-0 w-full h-full select-none pointer-events-none z-0 overflow-hidden">
      <Canvas
        camera={{ position: [0, 0, 5.5], fov: 40 }}
        gl={{ antialias: true, alpha: true }}
      >
        <ambientLight intensity={0.15} />
        {/* Crisp lighting to highlight the metallic edges */}
        <directionalLight position={[4, 5, 3]} intensity={1.8} />
        <pointLight position={[-4, -5, -2]} intensity={0.6} />
        <spotLight position={[0, 8, 2]} intensity={1.2} angle={0.4} penumbra={1} />
        <MonolithMesh />
      </Canvas>
    </div>
  );
}
