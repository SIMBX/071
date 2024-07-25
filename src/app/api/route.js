export async function GET() {
    try {
      return new Response(JSON.stringify({ message: "GET DATA OK"}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    } catch (error) {
      return new Response(JSON.stringify({ error: "Internal Server Error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
}


export async function POST() {
    try {
      return new Response(JSON.stringify({ message: "POST DATA OK"}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    } catch (error) {
      return new Response(JSON.stringify({ error: "Internal Server Error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
}

export async function PUT() {
    try {
      return new Response(JSON.stringify({ message: "PUT DATA OK"}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    } catch (error) {
      return new Response(JSON.stringify({ error: "Internal Server Error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
}

export async function DELETE() {
    try {
      return new Response(JSON.stringify({ message: "DELETE DATA OK"}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    } catch (error) {
      return new Response(JSON.stringify({ error: "Internal Server Error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
}