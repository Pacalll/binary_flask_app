const dropzone = document.getElementById('dropzone');
const input = document.querySelector('input');

//EventListener for user click Event
//call upload method
dropzone.addEventListener('click', (e) => {
    input.click();
    input.onchange = (e) => {
        upload(e.target.files[0]);
    }
})

//EventListener for user dragover Event
//do nothing
dropzone.addEventListener('dragover', (e) =>{
    e.preventDefault();
})

//EventListener for user drop Event
//if user drops a "file" call upload method
dropzone.addEventListener('drop', async (e) =>{
    e.preventDefault();
    //Error handling if the uploaded file is not a "file"
    if (![...e.dataTransfer.items].every(item => item.kind === "file")){
        throw new Error("Not a file");
    }
    //Error handling if it more than one file
    if (e.dataTransfer.items.length > 1){
        throw new Error("Multiple Files !");
    }
    const fileArray = [...e.dataTransfer.files];
    const isFile = await new Promise((resolve) =>{
        const fr = new FileReader();
        fr.onprogress = (e) =>{
            if (e.loaded > 50){
                fr.abort();
                resolve(true);
            }
        }
        fr.onload = () => {resolve(true)}
        fr.onerror = () => {resolve(false)}
        fr.readAsArrayBuffer(e.dataTransfer.files[0])
    });
    if(!isFile){
        throw new Error("Could not read this file");
    }
    upload(fileArray[0]);
});

async function upload(file) {
    const fd = new FormData();
    fd.append('file', file);

    try {
        const response = await fetch('http://localhost:5000/upload', {
            method: 'POST',
            body: fd,
        });
        if (response.ok) {
            const data = await response.json();
            console.log(data);
        } else {
            console.error("Bad response");
        }
    } catch (error) {
        console.error("Network error", error);
    }
}