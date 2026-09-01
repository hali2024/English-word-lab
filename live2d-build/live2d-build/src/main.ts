import * as PIXI from 'pixi.js';
import { Live2DModel } from 'pixi-live2d-display';

(window as any).PIXI = PIXI;

const app = new PIXI.Application({
  resizeTo: window,
  backgroundAlpha: 0,
  antialias: true
});

document.body.appendChild(app.view as HTMLCanvasElement);

async function loadPet(modelPath: string, x: number) {
  const model = await Live2DModel.from(modelPath);

  model.anchor.set(0.5, 1);
  model.scale.set(0.18);
  model.x = x;
  model.y = window.innerHeight;

  app.stage.addChild(model);

  return model;
}

async function start() {
  await loadPet('/live2d/tororo/tororo.model3.json', 180);
  await loadPet('/live2d/hijiki/hijiki.model3.json', 380);
}

start();
