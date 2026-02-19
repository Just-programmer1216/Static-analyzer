window.onload = drawVB;
function drawVB() {
    const canvaVB = document.getElementById("CanvaVB");
    const ctxVB = canvaVB.getContext("2d");
    ctxVB.translate(130,0);
    ctxVB.lineWidth = 3;
    ctxVB.beginPath();
    ctxVB.moveTo(30, 30);
    ctxVB.lineTo(30, 120);
    ctxVB.lineTo(60, 120);
    ctxVB.lineTo(60, 180);
    ctxVB.lineTo(90, 180);
    ctxVB.lineTo(90, 120);
    ctxVB.lineTo(150, 120);
    ctxVB.lineTo(150, 30);
    ctxVB.lineTo(90, 30);
    ctxVB.lineTo(90, 90);
    ctxVB.lineTo(60, 90);
    ctxVB.lineTo(60, 30);
    ctxVB.closePath();
    ctxVB.stroke();

    
    const ctxrVB = canvaVB.getContext("2d");
    ctxrVB.translate(130,0);
    ctxrVB.lineWidth = 3;

    const gradient = ctxrVB.createLinearGradient(90, 90, 150, 90);
    gradient.addColorStop(0, "#006200");
    gradient.addColorStop(1, "#000002");
    ctxrVB.fillStyle = gradient;
    ctxrVB.strokeStyle = gradient;

    ctxrVB.beginPath();
    ctxrVB.moveTo(90, 90);
    ctxrVB.lineTo(90, 180);
    ctxrVB.lineTo(150, 180);
    ctxrVB.lineTo(150, 120);    
    ctxrVB.lineTo(180, 120);
    ctxrVB.lineTo(180, 180);
    ctxrVB.lineTo(210, 180);
    ctxrVB.lineTo(210, 90);
    ctxrVB.lineTo(180, 90);
    ctxrVB.lineTo(180, 30);
    ctxrVB.lineTo(150, 30);
    ctxrVB.lineTo(150, 90);
    ctxrVB.moveTo(90, 90);
    ctxrVB.closePath();
    ctxrVB.stroke();
    ctxrVB.fill();
}