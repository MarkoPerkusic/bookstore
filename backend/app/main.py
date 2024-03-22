from fastapi import FastAPI

app = FastAPI()


@app.get("/")
async def read_root():
    return {"message": "Welcome to the bookstore API!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
