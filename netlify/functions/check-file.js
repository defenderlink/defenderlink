import fetch from "node-fetch";
import fs from "fs";

export async function handler(event) {
  try {
    const body = JSON.parse(event.body);
    const fileContent = body.file; // ожидаем base64 строку
    const buffer = Buffer.from(fileContent, "base64");

    // Загружаем файл в VirusTotal
    const uploadResponse = await fetch("https://www.virustotal.com/api/v3/files", {
      method: "POST",
      headers: {
        "x-apikey": process.env.VIRUSTOTAL_API_KEY,
      },
      body: buffer,
    });

    const uploadResult = await uploadResponse.json();

    if (!uploadResponse.ok) {
      throw new Error(uploadResult.error?.message || "Ошибка загрузки файла");
    }

    const analysisId = uploadResult.data.id;

    // Проверяем статус анализа
    let analysisResult;
    let attempts = 0;

    while (attempts < 10) {
      const analysisResponse = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        {
          headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY },
        }
      );

      analysisResult = await analysisResponse.json();

      if (analysisResult.data?.attributes?.status === "completed") {
        break;
      }

      attempts++;
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }

    return {
      statusCode: 200,
      body: JSON.stringify({
        status: "ok",
        result: analysisResult.data?.attributes?.stats || {},
      }),
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ status: "error", message: error.message }),
    };
  }
}
